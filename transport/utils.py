import json
import time
from typing import NamedTuple, Iterator, List, Iterable, Callable

import gevent
import structlog
from eth_utils import to_normalized_address, decode_hex
from urllib3.exceptions import DecodeError

from raiden.exceptions import InvalidProtocolMessage
from raiden.messages import Message, RetrieableMessage, Delivered, Ping, Pong, SignedMessage
from raiden.messages import (
    from_dict as message_from_dict,
    decode as message_from_bytes
)
from raiden.transfer import views
from raiden.transfer.identifiers import QueueIdentifier
from raiden.transfer.state import QueueIdsToQueues
from raiden.utils import Address, pex
from raiden.utils.runnable import Runnable
from transport.node import Node as TransportNode
from transport.udp import utils as udp_utils

log = structlog.get_logger(__name__)


class MessageQueue(Runnable):
    """ A helper Runnable to send batched messages to recipient through transport """

    class _MessageData(NamedTuple):
        """ Small helper data structure for message queue """

        queue_identifier: QueueIdentifier
        message: Message
        text: str
        # generator that tells if the message should be sent now
        expiration_generator: Iterator[bool]

    def __init__(self, transport_node: TransportNode, recipient: Address):
        self.transport_node = transport_node
        self.recipient = recipient
        self._message_queue: List[MessageQueue._MessageData] = list()
        self._notify_event = gevent.event.Event()
        self._lock = gevent.lock.Semaphore()
        super().__init__()
        self.greenlet.name = f"RetryQueue " f"recipient:{pex(self.recipient)}"

    @property
    def log(self):
        return self.transport_node.log

    @staticmethod
    def _expiration_generator(
        timeout_generator: Iterable[float], now: Callable[[], float] = time.time
    ) -> Iterator[bool]:
        """Stateful generator that yields True if more than timeout has passed since previous True,
        False otherwise.

        Helper method to tell when a message needs to be retried (more than timeout seconds
        passed since last time it was sent).
        timeout is iteratively fetched from timeout_generator
        First value is True to always send message at least once
        """
        for timeout in timeout_generator:
            _next = now() + timeout  # next value is now + next generated timeout
            yield True
            while now() < _next:  # yield False while next is still in the future
                yield False

    def enqueue(self, queue_identifier: QueueIdentifier, message: Message):
        """ Enqueue a message to be sent, and notify main loop """
        assert queue_identifier.recipient == self.recipient
        with self._lock:
            already_queued = any(
                queue_identifier == data.queue_identifier and message == data.message
                for data in self._message_queue
            )
            if already_queued:
                self.log.warning(
                    "Message already in queue - ignoring",
                    recipient=pex(self.recipient),
                    queue=queue_identifier,
                    message=message,
                )
                return
            timeout_generator = udp_utils.timeout_exponential_backoff(
                self.transport_node.config["retries_before_backoff"],
                self.transport_node.config["retry_interval"],
                self.transport_node.config["retry_interval"] * 10,
            )
            expiration_generator = self._expiration_generator(timeout_generator)
            self._message_queue.append(
                MessageQueue._MessageData(
                    queue_identifier=queue_identifier,
                    message=message,
                    text=json.dumps(message.to_dict()),
                    expiration_generator=expiration_generator,
                )
            )
        self.notify()

    def notify(self):
        """ Notify main loop to check if anything needs to be sent """
        with self._lock:
            self._notify_event.set()

    def _check_and_send(self):
        """Check and send all pending/queued messages that are not waiting on retry timeout

        After composing the to-be-sent message, also message queue from messages that are not
        present in the respective SendMessageEvent queue anymore
        """
        if not self.transport_node.greenlet:
            self.log.warning("Can't retry", reason="Transport not yet started")
            return
        if self.transport_node.stop_event.ready():
            self.log.warning("Can't retry", reason="Transport stopped")
            return

        # During startup global messages have to be sent first
        self.transport_node.enqueue_global_messages()

        self.log.debug("Retrying message", recipient=to_normalized_address(self.recipient))

        message_texts = [
            data.text
            for data in self._message_queue
            # if expired_gen generator yields False, message was sent recently, so skip it
            if next(data.expiration_generator)
        ]

        def message_is_in_queue(data: MessageQueue._MessageData) -> bool:
            return any(
                isinstance(data.message, RetrieableMessage)
                and send_event.message_identifier == data.message.message_identifier
                for send_event in self._queueids_to_queues[data.queue_identifier]
            )

        # clean after composing, so any queued messages (e.g. Delivered) are sent at least once
        for msg_data in self._message_queue[:]:
            remove = False
            if isinstance(msg_data.message, (Delivered, Ping, Pong)):
                # e.g. Delivered, send only once and then clear
                # TODO: Is this correct? Will a missed Delivered be 'fixed' by the
                #       later `Processed` message?
                remove = True
            elif msg_data.queue_identifier not in self._queueids_to_queues:
                remove = True
                self.log.debug(
                    "Stopping message send retry",
                    queue=msg_data.queue_identifier,
                    message=msg_data.message,
                    reason="Raiden queue is gone",
                )
            elif not message_is_in_queue(msg_data):
                remove = True
                self.log.debug(
                    "Stopping message send retry",
                    queue=msg_data.queue_identifier,
                    message=msg_data.message,
                    reason="Message was removed from queue",
                )

            if remove:
                self._message_queue.remove(msg_data)

        if message_texts:
            self.log.debug("Send", recipient=pex(self.recipient), messages=message_texts)
            self.transport_node.send_message("\n".join(message_texts), self.recipient)

    @property
    def _queueids_to_queues(self) -> QueueIdsToQueues:
        chain_state = views.state_from_raiden(self.transport_node.raiden_service)
        return views.get_all_messagequeues(chain_state)

    def _run(self):
        msg = f"_RetryQueue started before transport.raiden_service is set"
        assert self.transport_node.raiden_service is not None, msg
        self.greenlet.name = (
            f"RetryQueue "
            f"node:{pex(self.transport_node.raiden_service.address)} "
            f"recipient:{pex(self.recipient)}"
        )
        # run while transport parent is running
        while not self.transport_node.stop_event.ready():
            # once entered the critical section, block any other enqueue or notify attempt
            with self._lock:
                self._notify_event.clear()
                if self._message_queue:
                    self._check_and_send()
            # wait up to retry_interval (or to be notified) before checking again
            self._notify_event.wait(self.transport_node.config["retry_interval"])

    def __str__(self):
        return self.greenlet.name

    def __repr__(self):
        return f"<{self.__class__.__name__} for {to_normalized_address(self.recipient)}>"


def validate_and_parse_messages(data, peer_address) -> List[Message]:
    """
    This function receives a string data that represents one or more raiden messages. The function parses
    the data and convert it into one or many Raiden Messages.
    @param data: a string that contains one or more messages
    @param peer_address: the sender of that data
    @return a list of raiden messages
    """
    messages = list()
    if not isinstance(data, str):
        log.warning(
            "Received ToDevice Message body not a string",
            message_data=data,
            peer_address=pex(peer_address),
        )
        return []

    if data.startswith("0x"):
        try:
            message = message_from_bytes(decode_hex(data))
            if not message:
                raise InvalidProtocolMessage
        except (DecodeError, AssertionError) as ex:
            log.warning(
                "Can't parse ToDevice Message binary data",
                message_data=data,
                peer_address=pex(peer_address),
                _exc=ex,
            )
            return []
        except InvalidProtocolMessage as ex:
            log.warning(
                "Received ToDevice Message binary data is not a valid message",
                message_data=data,
                peer_address=pex(peer_address),
                _exc=ex,
            )
            return []
        else:
            messages.append(message)

    else:
        for line in data.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                message_dict = json.loads(line)
                message = message_from_dict(message_dict)
            except (UnicodeDecodeError, json.JSONDecodeError) as ex:
                log.warning(
                    "Can't parse ToDevice Message data JSON",
                    message_data=line,
                    peer_address=pex(peer_address),
                    _exc=ex,
                )
                continue
            except InvalidProtocolMessage as ex:
                log.warning(
                    "ToDevice Message data JSON are not a valid ToDevice Message",
                    message_data=line,
                    peer_address=pex(peer_address),
                    _exc=ex,
                )
                continue
            if not isinstance(message, SignedMessage):
                log.warning(
                    "ToDevice Message not a SignedMessage!",
                    message=message,
                    peer_address=pex(peer_address),
                )
                continue
            # TODO message must be signed by sender
            messages.append(message)
    return messages
