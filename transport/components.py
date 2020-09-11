from raiden.messages import Message
from raiden.transfer.identifiers import QueueIdentifier


class Params:
    """
    Params contains any necessary additional parameters for Raiden Messages to be successfully sent
    through whatever transport layer implementation picks them up.
    """

    def __init__(self, queue_identifier: QueueIdentifier):
        self.queue_identifier = queue_identifier
        """
        The QueueIdentifier coming from the (upper) Lumino business logic layer.
        """


class Message:
    """
    Message is a wrapper class which embeds a Raiden Message, plus any optional transport layer params.
    """

    def __init__(self, raiden_message: Message, transport_params: Params = None):
        self.raiden_message: raiden_message
        self.transport_params: transport_params
