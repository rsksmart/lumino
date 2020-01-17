from typing import Dict, Any

from raiden.lightclient.lightclientmessages.abstract_message_content import AbstractMessageContent
from raiden.lightclient.lightclientmessages.light_client_protocol_message import LightClientProtocolMessageType


class HubMessage:
    """ Representation of response to a LC request """

    def __init__(
        self,
        internal_msg_identifier: int,
        message_type: LightClientProtocolMessageType,
        message_content: AbstractMessageContent
    ):
        assert isinstance(message_content,
                          AbstractMessageContent), "Message content must implement AbstractMessageContent"
        self.internal_msg_identifier = internal_msg_identifier
        self.message_type = message_type
        self.message_content = message_content

    def to_dict(self) -> Dict[str, Any]:
        result_dict = {
            "internal_msg_identifier": self.internal_msg_identifier,
            "message_type": str(self.message_type),
            "message_content": self.message_content.to_dict()
        }
        return result_dict
