import string

from raiden.messages import Message


class LightClientProtocolMessage:
    """ Representation of light client message send or received. """

    def __init__(
        self,
        is_signed: bool,
        message_order: int,
        light_client_payment_id: int,
        identifier: string,
        unsigned_message: Message = None,
        signed_message: Message = None
    ):
        self.identifier = int(identifier)
        self.is_signed = is_signed
        self.message_order = message_order
        self.unsigned_message = unsigned_message
        self.signed_message = signed_message
        self.light_client_payment_id = light_client_payment_id

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
            "unsigned_message": unsigned_msg_dict,
            "signed_message": signed_msg_dict,
            "light_client_payment_id": self.light_client_payment_id
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
        self.unsigned_message = light_client_protocol_message.unsigned_message
        self.signed_message = light_client_protocol_message.signed_message

