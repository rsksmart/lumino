import string
from enum import Enum

from raiden.messages import Message
from raiden.utils.typing import AddressHex


class LightClientProtocolMessageType(Enum):
    PaymentSuccessful = "PaymentSuccessful"
    PaymentFailure = "PaymentFailure"
    PaymentExpired = "PaymentExpired"
    SettlementRequired = "SettlementRequired"
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
        unsigned_message: Message = None,
        signed_message: Message = None,
        internal_msg_identifier: int = None,
        sender_light_client_address: AddressHex = None,
        receiver_light_client_address: AddressHex = None
    ):
        self.identifier = int(identifier)
        self.is_signed = is_signed
        self.message_order = message_order
        self.message_type = message_type
        self.unsigned_message = unsigned_message
        self.signed_message = signed_message
        self.light_client_payment_id = light_client_payment_id
        self.internal_msg_identifier = internal_msg_identifier
        self.sender_light_client_address = sender_light_client_address
        self.receiver_light_client_address = receiver_light_client_address


    def to_dict(self):
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
            "sender_light_client_address": self.sender_light_client_address,
            "receiver_light_client_address": self.receiver_light_client_address

        }
        return result


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
        self.sender_light_client_address = light_client_protocol_message.sender_light_client_address
        self.receiver_light_client_address = light_client_protocol_message.receiver_light_client_address


