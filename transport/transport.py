from abc import ABC, abstractmethod

from raiden.messages import Message
from raiden.transfer.identifiers import QueueIdentifier
from raiden.utils import Address


class TransportLayer(ABC):

    def __init__(self, address: Address):
        super().__init__()  # init parent classes
        self._address = address
        # more fields can be initialized here, if needed

    # source for messages transmitted over this layer
    def address(self):
        return self._address

    @abstractmethod
    def send_async(self, queue_identifier: QueueIdentifier, message: Message):
        # queue the message for sending to recipient in the queue_identifier.
        # it may be called before transport is started, to initialize message queues.
        # the actual sending will be started only when the transport is started.
        pass

    @abstractmethod
    def start_health_check(self, address: Address):
        # start healthcheck (status monitoring) for a peer.
        # it also whitelists the address to answer invites and listen for messages.
        pass

    @abstractmethod
    def whitelist(self, address: Address):
        # whitelist peer address from which to receive communications.
        # this may be called before transport is started, to ensure events generated during start are handled properly.
        pass
