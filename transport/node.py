from abc import ABC, abstractmethod
from typing import Any

from raiden.messages import Message
from raiden.utils import Address


class Node(ABC):
    """
    Node is an abstraction that represents a single address (belonging to regular node or one registered as a light
    client) managed by the transport layer of the running Lumino node.
    This address can work both as a sender or a receiver of communications in the context of transport operations.
    It should implement concrete methods which have the responsibility of doing the actual sending and receiving of
    messages through the transport layer that manages it.
    """

    def __init__(self, address: Address):
        """
        The address represented by the Node in the context of communications.
        Messages to be received by this Node should be have this address as the message receiver.
        Messages to be sent from this Node should have this address as the message sender.
        """
        self.address = address

    @abstractmethod
    def start(self, raiden_service: 'RaidenService', message_handler: 'MessageHandler', prev_auth_data: str):
        """
        Start the transport node.
        """

    @abstractmethod
    def stop(self):
        """
        Stop the transport node.
        """

    @abstractmethod
    def send_message(self, message: Message, recipient: Address):
        """
        Send a message to the recipient.
        This method may be called before the transport node is started, but the actual message sending
        should only be attempted when the transport node is started.
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
        Add a callback function to be executed once the transport node is halted due to an exception.
        """

    @abstractmethod
    def join(self, timeout=None):
        """
        Wait until the transport node finishes its pending tasks or the given timeout passes.
        """
