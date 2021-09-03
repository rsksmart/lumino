from raiden.messages import Message as RaidenMessage
from raiden.transfer.identifiers import QueueIdentifier
from raiden.utils import Address


class MessageParams:
    """
    MessageParams contains any necessary additional parameters for Raiden Messages to be successfully sent
    through whatever transport layer implementation picks them up.
    """

    def __init__(self, queue_identifier: QueueIdentifier = None):
        self.queue_identifier = queue_identifier
        """
        The QueueIdentifier coming from the (upper) Lumino business logic layer.
        """


class Message:
    """
    Message is a wrapper class which embeds a Raiden Message, plus any optional transport layer params.
    """

    def __init__(self, raiden_message: RaidenMessage, params: MessageParams = None):
        self.raiden_message = raiden_message
        self.params = params

    @classmethod
    def wrap(cls, queue_identifier: QueueIdentifier, raiden_message: RaidenMessage) -> ("Message", Address):
        """
        Takes a queue identifier, a raiden message and wraps these fields in a transport message and extracts the
        recipient, with the purpose of sending these through a transport layer.
        """
        params = MessageParams(queue_identifier=queue_identifier)
        return Message(raiden_message, params), queue_identifier.recipient

    @classmethod
    def unwrap(cls, transport_message: "Message") -> (RaidenMessage, QueueIdentifier):
        """
        Takes a transport layer message and extracts the embedded Raiden message and its corresponding
        queue identifier from its parameters, with the purpose of processing it in a transport layer.
        """
        return transport_message.raiden_message, transport_message.params.queue_identifier
