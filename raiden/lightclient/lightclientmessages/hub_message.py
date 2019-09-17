from typing import Dict, Any

from eth_utils import encode_hex

from raiden.messages import Message
from raiden.utils import Secret


class HubMessage:
    """ Representation of response to a LC request """

    def __init__(
        self,
        message_id: int,
        message_order: int,
        payment_secret : Secret,
        message: Message
    ):
        self.message_id = message_id
        self.message_order = message_order
        self.payment_secret = payment_secret
        self.message = message

    def to_dict(self) -> Dict[str, Any]:

        result_dict = {
            "message_id": self.message_id,
            "message_order" : self.message_order,
            "payment_secret" : encode_hex(self.payment_secret),
            "message": self.message.to_dict()

        }

        return result_dict
