from abc import ABC, abstractmethod

from raiden.message_handler import MessageHandler
from raiden.messages import Message
from raiden.raiden_service import RaidenService
from raiden.transfer.identifiers import QueueIdentifier
from raiden.utils import Address


class TransportLayer(ABC):

    def __init__(self, address: Address):
        self._address = address  # source for messages transmitted over this layer

    def address(self):
        return self._address

    @abstractmethod
    def send_async(self, queue_identifier: QueueIdentifier, message: Message):
        """
        Queue the message for sending to recipient in the queue_identifier.
        It may be called before transport is started, to initialize message queues.
        The actual sending will be started only when the transport is started.
        """

    @abstractmethod
    def start_health_check(self, address: Address):
        """
        Start health-check (status monitoring) for a peer.
        It also whitelists the address to answer invites and listen for messages.
        """

    @abstractmethod
    def whitelist(self, address: Address):
        """
        Whitelist peer address from which to receive communications.
        This may be called before transport is started, to ensure events generated during start are handled properly.
        """

    @abstractmethod
    def start(self, raiden_service: RaidenService, message_handler: MessageHandler, prev_auth_data: str):
        """
        Start the transport layer.
        """