from abc import ABC, abstractmethod
from typing import Any

from raiden.message_handler import MessageHandler
from raiden.messages import Message
from raiden.raiden_service import RaidenService
from raiden.transfer.identifiers import QueueIdentifier
from raiden.utils import Address


class Node(ABC):

    def __init__(self, address: Address):
        """
        The address represented by the Node in the context of communications.
        Messages to be received by this Node should be have this address as the message receiver.
        Messages to be sent from this Node should have this address as the message sender.
        """
        self._address = address  

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
    def link_exception(self, callback: Any):
        """
        Add a callback function to be executed once the transport layer is halted due to an exception.
        """

    @abstractmethod
    def join(self, timeout=None):
        """
        Wait until the transport layer finishes its pending tasks or the given timeout passes.
        """
