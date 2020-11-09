import json
import time

import gevent
import structlog
from eth_utils import to_normalized_address
from gevent.event import Event
from gevent.lock import Semaphore
from raiden.messages import (
    Message,
    Delivered,
    Ping,
    Pong,
    RetrieableMessage,
)
from raiden.transfer.identifiers import QueueIdentifier
from raiden.utils import pex
from raiden.utils.runnable import Runnable
from raiden.utils.typing import (
    Address,
    Callable,
    Iterable,
    Iterator,
    List,
    NamedTuple,
    NewType,
)
from transport.udp import utils as udp_utils

log = structlog.get_logger(__name__)

_RoomID = NewType("_RoomID", str)


class _RetryQueue(Runnable):
    """ A helper Runnable to send batched messages to receiver through transport """

    class _MessageData(NamedTuple):
        """ Small helper data structure for message queue """

        queue_identifier: QueueIdentifier
        message: Message
        text: str
        # generator that tells if the message should be sent now
        expiration_generator: Iterator[bool]

    def __init__(self, transport: "MatrixNode", receiver: Address):
        self.transport = transport
        self.receiver = receiver
        self._message_queue: List[_RetryQueue._MessageData] = list()
        self._notify_event = gevent.event.Event()
        self._lock = gevent.lock.Semaphore()
        super().__init__()
        self.greenlet.name = f"RetryQueue " f"recipient:{pex(self.receiver)}"

    @property
    def log(self):
        return self.transport.log

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
        assert queue_identifier.recipient == self.receiver
        with self._lock:
            already_queued = any(
                queue_identifier == data.queue_identifier and message == data.message
                for data in self._message_queue
            )
            if already_queued:
                self.log.warning(
                    "Message already in queue - ignoring",
                    receiver=pex(self.receiver),
                    queue=queue_identifier,
                    message=message,
                )
                return
            timeout_generator = udp_utils.timeout_exponential_backoff(
                self.transport._config["retries_before_backoff"],
                self.transport._config["retry_interval"],
                self.transport._config["retry_interval"] * 10,
            )
            expiration_generator = self._expiration_generator(timeout_generator)
            self._message_queue.append(
                _RetryQueue._MessageData(
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
        if not self.transport.greenlet:
            self.log.warning("Can't retry", reason="Transport not yet started")
            return
        if self.transport._stop_event.ready():
            self.log.warning("Can't retry", reason="Transport stopped")
            return

        if self.transport._prioritize_global_messages:
            # During startup global messages have to be sent first
            self.transport._global_send_queue.join()

        self.log.debug("Retrying message", receiver=to_normalized_address(self.receiver))

        message_texts = [
            data.text
            for data in self._message_queue
            # if expired_gen generator yields False, message was sent recently, so skip it
            if next(data.expiration_generator)
        ]

        def message_is_in_queue(data: _RetryQueue._MessageData) -> bool:
            return any(
                isinstance(data.message, RetrieableMessage)
                and send_event.message_identifier == data.message.message_identifier
                for send_event in self.transport._queueids_to_queues[data.queue_identifier]
            )

        # clean after composing, so any queued messages (e.g. Delivered) are sent at least once
        for msg_data in self._message_queue[:]:
            remove = False
            if isinstance(msg_data.message, (Delivered, Ping, Pong)):
                # e.g. Delivered, send only once and then clear
                # TODO: Is this correct? Will a missed Delivered be 'fixed' by the
                #       later `Processed` message?
                remove = True
            elif msg_data.queue_identifier not in self.transport._queueids_to_queues:
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
            self.log.debug("Send", receiver=pex(self.receiver), messages=message_texts)
            self.transport._send_raw(self.receiver, "\n".join(message_texts))

    def _run(self):
        msg = f"_RetryQueue started before transport._raiden_service is set"
        assert self.transport._raiden_service is not None, msg
        self.greenlet.name = (
            f"RetryQueue "
            f"node:{pex(self.transport._raiden_service.address)} "
            f"recipient:{pex(self.receiver)}"
        )
        # run while transport parent is running
        while not self.transport._stop_event.ready():
            # once entered the critical section, block any other enqueue or notify attempt
            with self._lock:
                self._notify_event.clear()
                if self._message_queue:
                    self._check_and_send()
            # wait up to retry_interval (or to be notified) before checking again
            self._notify_event.wait(self.transport._config["retry_interval"])

    def __str__(self):
        return self.greenlet.name

    def __repr__(self):
        return f"<{self.__class__.__name__} for {to_normalized_address(self.receiver)}>"
