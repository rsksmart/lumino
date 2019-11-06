from typing import Dict, Any
from raiden.messages import Message


class HubMessage:
    """ Representation of response to a LC request """

    def __init__(
        self,
        message_id: int,
        message_order: int,
        message: Message
    ):
        self.message_id = message_id
        self.message_order = message_order
        self.message = message

    def to_dict(self) -> Dict[str, Any]:

        result_dict = {
            "message_id": self.message_id,
            "message_order" : self.message_order,
            "message": self.message.to_dict()

        }

        return result_dict
