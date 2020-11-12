from typing import Any, List, Dict, NewType, Union

import structlog
from eth_utils import to_checksum_address, is_binary_address
from gevent import Greenlet, killall, wait
from gevent.event import Event
from greenlet import GreenletExit

from raiden.exceptions import InvalidAddress, UnknownAddress, UnknownTokenAddress
from raiden.message_handler import MessageHandler
from raiden.messages import Message, SignedRetrieableMessage, SignedMessage, Delivered, Processed
from raiden.raiden_service import RaidenService
from raiden.transfer import views
from raiden.transfer.identifiers import QueueIdentifier
from raiden.transfer.mediated_transfer.events import CHANNEL_IDENTIFIER_GLOBAL_QUEUE
from raiden.transfer.state import QueueIdsToQueues
from raiden.utils import Address, pex
from raiden.utils.runnable import Runnable
from transport.matrix.utils import _RetryQueue
from transport.message import Message as TransportMessage
from transport.node import Node as TransportNode
from transport.rif_comms.client import RifCommsClient
from transport.rif_comms.proto.api_pb2 import Notification

_RoomID = NewType("_RoomID", str)
log = structlog.get_logger(__name__)


class RifCommsNode(TransportNode, Runnable):
    log = log

    def __init__(self, address: Address, config: dict):
        TransportNode.__init__(self, address)
        Runnable.__init__(self)
        self._config = config
        self._raiden_service: RaidenService = None

        self._rif_comms_connect_stream : Notification = None
        self._client = RifCommsClient(to_checksum_address(address), self._config["grpc_endpoint"])
        print("RifCommsNode init on grpc endpoint: {}".format(self._config["grpc_endpoint"]))

        self._greenlets: List[Greenlet] = list()  # TODO why we need this? how it works the _spawn
        self._address_to_message_queue: Dict[Address, _RetryQueue] = dict()  # TODO RetryQueue is on matrix package

        self._stop_event = Event()  # TODO used on handle message and another points, pending review
        self._stop_event.set()

        self.log = log.bind(node_address=pex(self.address))

    @property
    def _queueids_to_queues(self) -> QueueIdsToQueues:
        chain_state = views.state_from_raiden(self._raiden_service)
        return views.get_all_messagequeues(chain_state)

    def start(self, raiden_service: RaidenService, message_handler: MessageHandler, prev_auth_data: str):
        if not self._stop_event.ready():
            raise RuntimeError(f"{self!r} already started")
        self._stop_event.clear()
        self._raiden_service = raiden_service
        self._rif_comms_connect_stream = self._client.connect()
        self._client.get_peer_id(
            to_checksum_address(to_checksum_address(raiden_service.address)))  # TODO remove when blocking grpc api bug solved

        # TODO matrix node here invokes inventory_rooms that sets the handle_message callback
        # TODO here we must also check for new messages as the matrix node does with   self._client.start_listener_thread()
        #         self._client.sync_thread.link_exception(self.on_error)
        #         self._client.sync_thread.link_value(on_success)
        #         self.greenlets = [self._client.sync_thread]
        for message_queue in self._address_to_message_queue.values():
            if not message_queue:
                self.log.debug("Starting message_queue", message_queue=message_queue)
                message_queue.start()
        self.log.debug("RIF Comms Node started", config=self._config)
        Runnable.start(self)

    def __repr__(self):
        if self._raiden_service is not None:
            node = f" node:{pex(self._raiden_service.address)}"
        else:
            node = ""

        return f"<{self.__class__.__name__}{node} id:{id(self)}>"

    def _run(self) -> None:
        # TODO ActionUpdateTransportAuthData?
        # TODO which is the  Runnable main method, that perform wait on long-running subtasks ?"
        """ Runnable main method, perform wait on long-running subtasks """
        # dispatch auth data on first scheduling after start
        self.greenlet.name = f"RifCommsNode._run node:{pex(self._raiden_service.address)}"
        try:
            # waits on _stop_event.ready()
            # children crashes should throw an exception here
            self.log.info("RIF Comms _run")
        except GreenletExit:  # killed without exception
            self._stop_event.set()
            killall(self.greenlets)  # kill children
            raise  # re-raise to keep killed status
        except Exception:
            self.stop()  # ensure cleanup and wait on subtasks
            raise

    def stop(self):
        """
        Try to gracefully stop the greenlet synchronously

        Stop isn't expected to re-raise greenlet _run exception
        (use self.greenlet.get() for that),
        but it should raise any stop-time exception

        Disconnects from RIF Communications node
        """
        if self._stop_event.ready():
            return
        self._stop_event.set()

        for message_queue in self._address_to_message_queue.values():
            if message_queue:  # if message_queue.greenlet is not None
                message_queue.notify()  # if we need to send something, this is the time

        # TODO we must stop the listener thread if present on this implementation
        # self._client.stop_listener_thread()  # stop sync_thread, wait client's greenlets

        # wait own greenlets, no need to get on them, exceptions should be raised in _run()
        wait(self._greenlets + [r.greenlet for r in self._address_to_message_queue.values()])

        # TODO we must end rif comms communication and grpc session
        self._client.disconnect()

        self.log.debug("RIF Comms Node stopped", config=self._config)
        try:
            del self.log
        except AttributeError:
            # During shutdown the log attribute may have already been collected
            pass
        # parent may want to call get() after stop(), to ensure _run errors are re-raised
        # we don't call it here to avoid deadlock when self crashes and calls stop() on finally

    def send_message(self, message: TransportMessage, recipient: Address):
        """Queue the message for sending to recipient in the queue_identifier

        It may be called before transport is started, to initialize message queues
        The actual sending is started only when the transport is started
        """
        raiden_message, queue_identifier = TransportMessage.unwrap(message)

        # even if transport is not started, can run to enqueue messages to send when it starts
        if not is_binary_address(recipient):
            raise ValueError("Invalid address {}".format(pex(recipient)))

        # These are not protocol messages, but transport specific messages
        if isinstance(raiden_message, (Ping, Pong)):
            raise ValueError(
                "Do not use send_message for {} messages".format(raiden_message.__class__.__name__)
            )

        self.log.info(
            "Send message",
            recipient=pex(recipient),
            message=raiden_message,
            queue_identifier=queue_identifier,
        )

        self._enqueue_message(queue_identifier, raiden_message)

    def _enqueue_message(self, queue_identifier: QueueIdentifier, message: Message):
        queue = self._get_queue(queue_identifier.recipient)
        queue.enqueue(queue_identifier=queue_identifier, message=message)

    def _get_queue(self, receiver: Address) -> _RetryQueue:
        """ Construct and return a _RetryQueue for receiver """
        if receiver not in self._address_to_message_queue:
            queue = _RetryQueue(transport=self, receiver=receiver)
            self._address_to_message_queue[receiver] = queue
            # Always start the _RetryQueue, otherwise `stop` will block forever
            # waiting for the corresponding gevent.Greenlet to complete. This
            # has no negative side-effects if the transport has stopped becausecreate_light_client_payment
            # the queue itself checks the transport running state.
            queue.start()
        return self._address_to_message_queue[receiver]

    # TODO exception handling rif comms client
    def _send_raw(self, receiver_address: Address, data: str):
        # Check if we have a subscription for that receiver address
        is_subscribed_to_receiver_topic = self._client.has_subscription(receiver_address).value
        if not is_subscribed_to_receiver_topic:
            # If not, create the topic subscription
            self._client.subscribe(receiver_address)  # TODO is this really needed in order to send msg to receiver?
        # Send the message
        self._client.send_message(receiver_address, data)
        self.log.info(
            "RIF Comms send raw", receiver=pex(receiver_address), data=data.replace("\n", "\\n")
        )

    def _handle_message(self, topic_id, data) -> bool:
        """ Handle text messages sent received on a topic  """
        if (
            self._stop_event.ready()
        ):
            # Ignore when stopped
            return False

        # TODO validate signature of the message

        messages = list()  # TODO validate_and_parse_message(event["content"]["body"], peer_address)

        if not messages:
            return False

        self.log.info(
            "Incoming messages",
            messages=messages,
            topic_id=pex(topic_id),
        )

        for message in messages:
            if not isinstance(message, (SignedRetrieableMessage, SignedMessage)):
                self.log.warning("Received invalid message", message=message)
            if isinstance(message, Delivered):
                self._receive_delivered(message)
            elif isinstance(message, Processed):
                self._receive_message(message)
            else:
                assert isinstance(message, SignedRetrieableMessage)
                self._receive_message(message)

        return True

    def _receive_delivered(self, delivered: Delivered):
        self.log.info(
            "Delivered message received", sender=pex(delivered.sender), message=delivered
        )

        assert self._raiden_service is not None
        self._raiden_service.on_message(delivered)

    def _receive_message(self, message: Union[SignedRetrieableMessage, Processed]):
        assert self._raiden_service is not None
        self.log.info(
            "RIF Comms Message received",
            node=pex(self._raiden_service.address),
            message=message,
            sender=pex(message.sender),
        )

        try:
            delivered_message = Delivered(delivered_message_identifier=message.message_identifier)
            self._raiden_service.sign(delivered_message)

            queue_identifier = QueueIdentifier(
                recipient=message.sender, channel_identifier=CHANNEL_IDENTIFIER_GLOBAL_QUEUE
            )
            self.send_message(*TransportMessage.wrap(queue_identifier, delivered_message))
            self._raiden_service.on_message(message)

        except (InvalidAddress, UnknownAddress, UnknownTokenAddress):
            self.log.warning("Exception while processing message", exc_info=True)
            return


    def start_health_check(self, address: Address):
        self.log.debug("Healthcheck", peer_address=pex(address))

    def whitelist(self, address: Address):
        self.log.debug("Whitelist", peer_address=pex(address))

    def link_exception(self, callback: Any):
        self.greenlet.link_exception(callback)

    def join(self, timeout=None):
        self.greenlet.join(timeout)


class RifCommsLightClientNode(RifCommsNode):

    def __init__(self, address: Address, config: dict, auth_params: dict):
        RifCommsNode.__init__(self, address, config)
