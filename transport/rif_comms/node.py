from typing import Any, Dict

import structlog
from eth_utils import is_binary_address
from gevent import killall, wait
from greenlet import GreenletExit

from raiden.exceptions import InvalidAddress, UnknownAddress, UnknownTokenAddress, InvalidProtocolMessage
from raiden.message_handler import MessageHandler
from raiden.messages import (
    Message as RaidenMessage,
    SignedRetrieableMessage,
    Delivered,
    Processed,
    Ping,
    Pong
)
from raiden.raiden_service import RaidenService
from raiden.transfer.identifiers import QueueIdentifier
from raiden.transfer.mediated_transfer.events import CHANNEL_IDENTIFIER_GLOBAL_QUEUE
from raiden.utils import pex
from raiden.utils.runnable import Runnable
from raiden.utils.typing import Address
from transport.message import Message as TransportMessage
from transport.node import Node as TransportNode
from transport.rif_comms.client import Client as RIFCommsClient
from transport.rif_comms.proto.api_pb2 import Notification
from transport.rif_comms.utils import notification_to_payload
from transport.utils import MessageQueue
from transport.utils import validate_and_parse_messages

log = structlog.get_logger(__name__)


class Node(TransportNode):
    _log = log

    def __init__(self, address: Address, config: dict):
        TransportNode.__init__(self, address)

        # set instance variables
        self._config = config
        self._raiden_service: RaidenService = None

        # set up comms node
        self._rif_comms_connect_stream: Notification = None
        self._our_topic_stream: Notification = None
        self._comms_client = RIFCommsClient(address, self._config["grpc_endpoint"])

        # initialize message queues
        self._address_to_message_queue: Dict[Address, MessageQueue] = dict()

        self._log = log.bind(node_address=pex(self.address))
        self.log.info("RIFCommsNode init on GRPC endpoint: {}".format(self._config["grpc_endpoint"]))

    def start(self, raiden_service: RaidenService, message_handler: MessageHandler, prev_auth_data: str):
        """
        Initialize transport fields, connect to RIF Comms Node, and start as Runnable.
        """
        self._raiden_service = raiden_service  # TODO: this should be set in __init__

        # check if node is already running
        if not self.stop_event.ready():
            raise RuntimeError(f"{self!r} already started")
        self.stop_event.clear()

        # connect to rif comms node
        # TODO: this shouldn't need to be assigned, it is only done because otherwise the code hangs
        self._rif_comms_connect_stream = self._comms_client.connect()
        # start pre-loaded message queues
        for message_queue in self._address_to_message_queue.values():
            if not message_queue.greenlet:
                self.log.debug("starting message_queue", message_queue=message_queue)
                message_queue.start()

        self.log.info("RIF Comms Node start", config=self._config)

        # start greenlet through the Runnable class; this will eventually call _run
        Runnable.start(self)

    def _receive_messages(self):
        """
        Iterate over the Notification stream and block thread to receive messages.
        """
        for notification in self._our_topic_stream:
            payload = notification_to_payload(notification)
            try:
                for raiden_message in validate_and_parse_messages(payload, None):
                    self.log.info("incoming message", message=raiden_message)
                    self._handle_message(raiden_message)
            except InvalidProtocolMessage:
                self.log.error("incoming message could not be processed", payload=payload)

    def _handle_message(self, message: RaidenMessage):
        """
        Handle received Raiden message.
        """
        if self.stop_event.ready():
            return  # ignore when node is stopped

        # process message if its type is expected
        if isinstance(message, (Delivered, Processed, SignedRetrieableMessage)):
            self.log.info(
                "Raiden message received",
                type=type(message),
                node=pex(self.address),
                message=message,
                sender=pex(message.sender),
            )

            try:
                # acknowledge to sender that their message was received
                # if the received Raiden message is of the Delivered type, no action needs to be taken
                if not isinstance(message, Delivered):
                    self._ack_message(message)
            except (InvalidAddress, UnknownAddress, UnknownTokenAddress):
                self.log.warning("exception while processing message", exc_info=True)
                return

            # once acknowledged, pass message to raiden service for business logic
            self._raiden_service.on_message(message)

        else:
            self.log.warning(
                "unexpected type of message received",
                type=type(message),
                node=pex(self.address),
                message=message,
            )

    def _ack_message(self, message: (Processed, SignedRetrieableMessage)):
        """
        Acknowledge a received Raiden message by sending a Delivered-type message back.
        """
        # put together Delivered-typed message to reply with
        delivered_message = Delivered(delivered_message_identifier=message.message_identifier)
        self._raiden_service.sign(delivered_message)

        queue_identifier = QueueIdentifier(
            recipient=message.sender, channel_identifier=CHANNEL_IDENTIFIER_GLOBAL_QUEUE
        )
        self.enqueue_message(*TransportMessage.wrap(queue_identifier, delivered_message))

    def _run(self, *args: Any, **kwargs: Any) -> None:
        """
        Runnable main method. Start a listener greenlet to listen for received messages in the background.
        """
        self.greenlet.name = f"RIFCommsNode._run node:{pex(self.address)}"
        _, self._our_topic_stream = self._comms_client.subscribe_to(self.address)
        try:
            # waits on stop_event.ready()
            # children crashes should throw an exception here
            self._receive_messages()
            self.log.info("RIF Comms Node _run. Listening for messages.")
        except GreenletExit:  # killed without exception
            self.stop_event.set()
            killall([self.greenlet])  # kill comms listener thread
            raise  # re-raise to keep killed status
        except Exception:
            self.stop()  # ensure cleanup and wait on subtasks
            raise

    def stop(self):
        """
        Try to gracefully stop the underlying greenlet synchronously.
        Stop isn't expected to re-raise greenlet _run exception
        (use self.greenlet.get() for that),
        but it should raise any stop-time exception.
        Also disconnect from RIF Communications node.
        """
        if self.stop_event.ready():
            return  # already stopped
        self.stop_event.set()

        for message_queue in self._address_to_message_queue.values():
            if message_queue.greenlet:
                message_queue.notify()  # if we need to send something, this is the time

        if self.greenlet:
            self.greenlet.kill()
            self.greenlet.get()

        # wait for our own greenlets, no need to get on them, exceptions should be raised in _run()
        wait([self.greenlet] + [r.greenlet for r in self._address_to_message_queue.values()])

        self._comms_client.disconnect()

        self.log.debug("RIF Comms Node stop", config=self._config)
        try:
            del self._log
        except AttributeError:
            # During shutdown the log attribute may have already been collected
            pass
        # parent may want to call get() after stop(), to ensure _run errors are re-raised
        # we don't call it here to avoid deadlock when self crashes and calls stop() on finally

    def enqueue_message(self, message: TransportMessage, recipient: Address):
        """
        Queue the message for sending to recipient.
        It may be called before transport is started, to initialize message queues.
        The actual sending is started only when the transport is started.
        """
        raiden_message, queue_identifier = TransportMessage.unwrap(message)

        if not is_binary_address(recipient):
            raise ValueError("Invalid address {}".format(pex(recipient)))

        # these are not protocol messages, but transport-specific messages
        if isinstance(raiden_message, (Ping, Pong)):
            raise ValueError("Do not use send_message for {} messages".format(raiden_message.__class__.__name__))

        self.log.info(
            "RIF Comms enqueue message",
            recipient=pex(recipient),
            message=raiden_message,
            queue_identifier=queue_identifier,
        )

        message_queue = self._get_queue(queue_identifier.recipient)
        message_queue.enqueue(queue_identifier=queue_identifier, message=raiden_message)

    def _get_queue(self, recipient: Address) -> MessageQueue:
        """
        Return a MessageQueue for recipient; create one if it does not exist.
        """
        if recipient not in self._address_to_message_queue:
            queue = MessageQueue(transport_node=self, recipient=recipient)
            self._address_to_message_queue[recipient] = queue
            # Always start the MessageQueue, otherwise stop() will block forever
            # waiting for the corresponding gevent.Greenlet to complete. This
            # has no negative side-effects if the transport has stopped because
            # the queue itself checks the transport running state.
            queue.start()
        return self._address_to_message_queue[recipient]

    def enqueue_global_messages(self):
        pass

    def send_message(self, payload: str, recipient: Address):
        """
        Send text message through the RIF Comms client.
        """
        self._comms_client.subscribe_to(recipient)
        # send the message
        self._comms_client.send_message(payload, recipient)  # TODO: exception handling for RIF Comms client
        self.log.info(
            "RIF Comms send message", message_payload=payload.replace("\n", "\\n"), recipient=pex(recipient)
        )

    def start_health_check(self, address: Address):
        self.log.debug("Healthcheck", peer_address=pex(address))

    def whitelist(self, address: Address):
        self.log.debug("Whitelist", peer_address=pex(address))

    def link_exception(self, callback: Any):
        self.greenlet.link_exception(callback)

    def join(self, timeout=None):
        self.greenlet.join(timeout)

    @property
    def raiden_service(self) -> 'RaidenService':
        return self._raiden_service

    @property
    def config(self) -> {}:
        return self._config

    @property
    def log(self):
        return self._log

    def __repr__(self):
        node = f" RIF Comms Transport node:{pex(self.address)}"
        return f"<{self.__class__.__name__}{node} id:{id(self)}>"


class LightClientNode(Node):

    def __init__(self, address: Address, config: dict):
        Node.__init__(self, address, config)

    def _handle_message(self, message: RaidenMessage):
        """
        Handle received Raiden message.
        """
        if self.stop_event.ready():
            return  # ignore when node is stopped

        # process message if its type is expected
        if isinstance(message, (Delivered, Processed, SignedRetrieableMessage)):
            self.log.info(
                "Raiden message received",
                type=type(message),
                node=pex(self.address),
                message=message,
                sender=pex(message.sender),
            )
            # Pass message to raiden service for business logic. The message will be stored on the HUB database.
            self._raiden_service.on_message(message, True)
        else:
            self.log.warning(
                "unexpected type of message received",
                type=type(message),
                node=pex(self.address),
                message=message,
            )

    def _ack_message(self, message: (Processed, SignedRetrieableMessage)):
        """
        Acks must be signed by the Light client first, therefore the transport is not in charge to create and send
        the Delivered messages.
        """
        raise Exception("Do not use _ack_message for light client transport")
