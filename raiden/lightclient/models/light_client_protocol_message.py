import string
from enum import Enum
from typing import Any, Dict

from eth_utils import to_checksum_address, to_canonical_address

from raiden.messages import Message
from raiden.utils.typing import AddressHex


class LightClientProtocolMessageType(Enum):
    PaymentSuccessful = "PaymentSuccessful"
    PaymentFailure = "PaymentFailure"
    PaymentExpired = "PaymentExpired"
    SettlementRequired = "SettlementRequired"
    RequestRegisterSecret = "RequestRegisterSecret"
    UnlockLightRequest = "UnlockLightRequest"
    PaymentRefund = "PaymentRefund"


class LightClientProtocolMessage:
    """ Representation of light client message send or received. """

    def __init__(
        self,
        is_signed: bool,
        message_order: int,
        light_client_payment_id: int,
        identifier: string,
        message_type: LightClientProtocolMessageType,
        light_client_address: AddressHex,
        unsigned_message: Message,
        signed_message: Message = None,
        internal_msg_identifier: int = None
    ):
        self.identifier = int(identifier)
        self.is_signed = is_signed
        self.message_order = message_order
        self.message_type = message_type
        self.unsigned_message = unsigned_message
        self.signed_message = signed_message
        self.light_client_payment_id = light_client_payment_id
        self.internal_msg_identifier = internal_msg_identifier
        self.light_client_address = light_client_address

    def to_dict(self) -> Dict[str, Any]:
        signed_msg_dict = None
        unsigned_msg_dict = None
        if self.unsigned_message is not None:
            unsigned_msg_dict = self.unsigned_message.to_dict()
        if self.signed_message is not None:
            signed_msg_dict = self.signed_message.to_dict()

        result = {
            "identifier": self.identifier,
            "is_signed": self.is_signed,
            "message_order": self.message_order,
            "message_type": self.message_type.value,
            "unsigned_message": unsigned_msg_dict,
            "signed_message": signed_msg_dict,
            "light_client_payment_id": self.light_client_payment_id,
            "internal_msg_identifier": self.internal_msg_identifier,
            "light_client_address": to_checksum_address(self.light_client_address)
        }
        return result

    def from_dict(self, dictionary: Dict[str, Any]):
        if dictionary["unsigned_message"]:
            self.unsigned_message = Message.from_dict(dictionary["unsigned_message"])
        if dictionary["signed_message"]:
            self.signed_message = Message.from_dict(dictionary["signed_message"])

        self.identifier = dictionary["identifier"]
        self.is_signed = dictionary["is_signed"]
        self.message_order = dictionary["message_order"]
        self.message_type = dictionary["message_type"]
        self.light_client_payment_id = dictionary["light_client_payment_id"]
        self.internal_msg_identifier = dictionary["internal_msg_identifier"]
        self.light_client_address = to_canonical_address(dictionary["light_client_address"])


class DbLightClientProtocolMessage:
    """ Db representation of light client message """

    def __init__(
        self,
        light_client_protocol_message: LightClientProtocolMessage
    ):
        self.identifier = light_client_protocol_message.identifier
        self.message_order = light_client_protocol_message.message_order
        self.light_client_payment_id = light_client_protocol_message.light_client_payment_id
        self.message_type = light_client_protocol_message.message_type
        self.unsigned_message = light_client_protocol_message.unsigned_message
        self.signed_message = light_client_protocol_message.signed_message
        self.light_client_address = light_client_protocol_message.light_client_address
