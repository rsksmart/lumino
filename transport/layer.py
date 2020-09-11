from abc import ABC, abstractmethod
from typing import Any

from raiden.message_handler import MessageHandler
from raiden.raiden_service import RaidenService
from raiden.utils import Address
from transport.components import Message


class TransportLayer(ABC):
    """
    TransportLayer is an abstraction which lays between the Lumino business logic layer and the
    lower layers of the system that take care of sending and receiving messages.
    """

    def __init__(self, address: Address):
        self._address = address
        """
        Source for messages transmitted over this layer.
        """

    @property
    def address(self):
        return self._address

    @abstractmethod
    def start(self, raiden_service: RaidenService, message_handler: MessageHandler, prev_auth_data: str):
        """
        Start the transport layer.
        """

    @abstractmethod
    def stop(self):
        """
        Stop the transport layer.
        """

    @abstractmethod
    def send_message(self, message: Message, recipient: Address):
        """
        Send a message to the recipient.
        This method may be called before the transport layer is started, but the actual message sending
        should only be attempted when the transport layer is started.
        """

    @abstractmethod
    def start_health_check(self, address: Address):
        """
        Start health-check (status monitoring) for an address.
        It also whitelists the address to listen for messages, invites or handshakes.
        """

    @abstractmethod
    def whitelist(self, address: Address):
        """
        Whitelist peer address from which to receive communications.
        This may be called before transport layer is started.
        """

    @abstractmethod
    def link_exception(self, callback: Any):
        """
        Add a callback function to be executed once the transport layer is halted due to an exception.
        """

    @abstractmethod
    def join(self, timeout=None):
        """
        Wait until the transport layer finishes its pending tasks or the given timeout passes.
        """
