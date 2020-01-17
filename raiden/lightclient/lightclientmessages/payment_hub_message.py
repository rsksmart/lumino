from typing import Dict, Any

from raiden.lightclient.lightclientmessages.abstract_message_content import AbstractMessageContent
from raiden.messages import Message


class PaymentHubMessage(AbstractMessageContent):
    """ Representation of response to a payment LC message request"""

    def __init__(
        self,
        payment_id: int,
        message_order: int,
        message: Message
    ):
        self.payment_id = payment_id
        self.message_order = message_order
        self.message = message

    def to_dict(self) -> Dict[str, Any]:
        result_dict = {
            "payment_id": self.payment_id,
            "message_order" : self.message_order,
            "message": self.message.to_dict()
        }
        return result_dict
