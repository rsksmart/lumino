import json
from typing import Any, List, Dict, Union

import structlog
from eth_utils import to_checksum_address, is_binary_address
from gevent import Greenlet, killall, wait, spawn
from gevent.event import Event
from greenlet import GreenletExit
from raiden.exceptions import InvalidAddress, UnknownAddress, UnknownTokenAddress
from raiden.message_handler import MessageHandler
from raiden.messages import (
    Message,
    SignedRetrieableMessage,
    SignedMessage, Delivered,
    Processed,
    Ping,
    Pong,
    from_dict as message_from_dict
)
from raiden.raiden_service import RaidenService
from raiden.transfer import views
from raiden.transfer.identifiers import QueueIdentifier
from raiden.transfer.mediated_transfer.events import CHANNEL_IDENTIFIER_GLOBAL_QUEUE
from raiden.transfer.state import QueueIdsToQueues
from raiden.utils import pex
from raiden.utils.runnable import Runnable
from raiden.utils.typing import Address
from transport.message import Message as TransportMessage
from transport.node import Node as TransportNode
from transport.rif_comms.client import RifCommsClient
from transport.rif_comms.proto.api_pb2 import Notification, ChannelNewData
from transport.utils import MessageQueue

log = structlog.get_logger(__name__)


class RifCommsNode(TransportNode):
    _log = log

    def __init__(self, address: Address, config: dict):
        TransportNode.__init__(self, address)
        self._config = config
        self._raiden_service: RaidenService = None

        self._rif_comms_connect_stream: Notification = None
        self._our_topic_stream: Notification = None
        self._our_topic_thread: Greenlet = None

        self._comms_client = RifCommsClient(to_checksum_address(address), self._config["grpc_endpoint"])
        print("RifCommsNode init on grpc endpoint: {}".format(self._config["grpc_endpoint"]))

        self._greenlets: List[Greenlet] = list()
        self._address_to_message_queue: Dict[Address, MessageQueue] = dict()

        self._stop_event = Event()
        self._stop_event.set()

        self._log = log.bind(node_address=pex(self.address))

    @property
    def _queueids_to_queues(self) -> QueueIdsToQueues:
        chain_state = views.state_from_raiden(self._raiden_service)
        return views.get_all_messagequeues(chain_state)

    def start(self, raiden_service: RaidenService, message_handler: MessageHandler, prev_auth_data: str):
        self._raiden_service = raiden_service

        # check if node is already running
        if not self._stop_event.ready():
            raise RuntimeError(f"{self!r} already started")
        self._stop_event.clear()

        # connect to rif comms node
        # TODO: this shouldn't need to be assigned, it is only done because otherwise the code hangs
        self._rif_comms_connect_stream = self._comms_client.connect()

        # subscribe to our own topic to receive messages
        self._listen_for_messages()

        # start pre-loaded message queues
        for message_queue in self._address_to_message_queue.values():
            if not message_queue.greenlet:
                self.log.debug("Starting message_queue", message_queue=message_queue)
                message_queue.start()

        # start greenlet
        self.log.debug("RIF Comms Node started", config=self._config)
        Runnable.start(self)

    def __repr__(self):
        node = f" node:{pex(self._raiden_service.address)}" if self._raiden_service else ""

        return f"<{self.__class__.__name__}{node} id:{id(self)}>"

    def _run(self) -> None:
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
            if message_queue.greenlet:
                message_queue.notify()  # if we need to send something, this is the time

        self.stop_listener_thread()  # stop sync_thread, wait for client's greenlets

        # wait for our own greenlets, no need to get on them, exceptions should be raised in _run()
        wait(self._greenlets + [r.greenlet for r in self._address_to_message_queue.values()])

        self._comms_client.disconnect()

        self.log.debug("RIF Comms Node stopped", config=self._config)
        try:
            del self._log
        except AttributeError:
            # During shutdown the log attribute may have already been collected
            pass
        # parent may want to call get() after stop(), to ensure _run errors are re-raised
        # we don't call it here to avoid deadlock when self crashes and calls stop() on finally

    def enqueue_message(self, message: TransportMessage, recipient: Address):
        """Queue the message for sending to recipient

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

        queue = self._get_queue(queue_identifier.recipient)
        queue.enqueue(queue_identifier=queue_identifier, message=raiden_message)

    def _get_queue(self, recipient: Address) -> MessageQueue:
        """ Construct and return a MessageQueue for recipient """
        if recipient not in self._address_to_message_queue:
            queue = MessageQueue(transport_node=self, recipient=recipient)
            self._address_to_message_queue[recipient] = queue
            # Always start the MessageQueue, otherwise `stop` will block forever
            # waiting for the corresponding gevent.Greenlet to complete. This
            # has no negative side-effects if the transport has stopped because create_light_client_payment
            # the queue itself checks the transport running state.
            queue.start()
        return self._address_to_message_queue[recipient]

    # TODO exception handling rif comms client
    def send_message(self, payload: str, recipient: Address):
        # Check if we have a subscription for that receiver address
        is_subscribed_to_receiver_topic = self._comms_client.has_subscription(recipient).value
        if not is_subscribed_to_receiver_topic:
            # If not, create the topic subscription
            self._comms_client.subscribe(recipient)  # TODO is this really needed in order to send msg to receiver?
        # Send the message
        self._comms_client.send_message(recipient, payload)
        self.log.info(
            "RIF Comms send raw", recipient=pex(recipient), data=payload.replace("\n", "\\n")
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

    def enqueue_global_messages(self):
        pass

    def start_health_check(self, address: Address):
        self.log.debug("Healthcheck", peer_address=pex(address))

    def whitelist(self, address: Address):
        self.log.debug("Whitelist", peer_address=pex(address))

    def link_exception(self, callback: Any):
        self.greenlet.link_exception(callback)

    def join(self, timeout=None):
        self.greenlet.join(timeout)

    def _listen_for_messages(self):
        """
        Start a listener greenlet to listen for received messages in the background.
        """
        our_address = to_checksum_address(self.raiden_service.address)
        self._our_topic_stream = self._comms_client.subscribe(our_address)
        # TODO: remove this after GRPC API request blocking is fixed
        self._comms_client.get_peer_id(our_address)
        self._our_topic_thread = spawn(self._receive_messages)
        self._our_topic_thread.name = f"RifCommsClient.listen_messages rsk_address:{self.address}"
        self._greenlets = [self._our_topic_thread]

    def _receive_messages(self):
        """
        Iterate over the Notification stream and blocks thread to receive messages
        """
        for notification in self._our_topic_stream:
            parsed_message = self.parse_topic_new_data(notification.channelNewData)
            if parsed_message:
                # TODO: handle message
                self.log.info(parsed_message)

    def stop_listener_thread(self):
        """ Kills message listener greenlet  """
        if self._our_topic_thread:
            self._our_topic_thread.kill()
            self._our_topic_thread.get()
        self._our_topic_thread = None

    @staticmethod
    def parse_topic_new_data(topic_new_data: ChannelNewData) -> Message:
        """
        :param topic_new_data: raw data received by the RIF Comms GRPC api
        :return: a raiden.Message
        """
        content = topic_new_data.data
        """
            topic_new_data has the following structure:
            from: "16Uiu2HAm8wq7GpkmTDqBxb4eKGfa2Yos79DabTgSXXF4PcHaDhWJ"
            data: "{\"type\":\"Buffer\",\"data\":[104,101,121]}"
            nonce: "\216f\225\232d\023e{"
            channel {
              channelId: "16Uiu2HAm9otWzXBcFm7WC2Qufp2h1mpRxK1oox289omHTcKgrpRA"
            }

        """
        if content:
            # We first transform the content of the topic new data to an object
            object_data = json.loads(content.decode())
            """
                Since the message is assigned to the 'data' key and encoded by the RIF Comms GRPC api
                we need to convert it to string.

                    data: "{\"type\":\"Buffer\",\"data\":[104,101,121]}"
            """
            string_message = bytes(object_data["data"]).decode()
            message_dict = json.loads(string_message)
            message = message_from_dict(message_dict)
            return message
        else:
            return None

    @property
    def raiden_service(self) -> 'RaidenService':
        return self._raiden_service

    @property
    def config(self) -> {}:
        return self._config

    @property
    def log(self):
        return self._log


class RifCommsLightClientNode(RifCommsNode):

    def __init__(self, address: Address, config: dict, auth_params: dict):
        RifCommsNode.__init__(self, address, config)
