from raiden.messages import Message





class LigthClientProtocolMessage:
    """ Representation of light client message send or received. """

    def __init__(
        self,
        identifier: int,
        is_signed: bool,
        message_order: int,
        light_client_payment_id: int,
        state_change_id: int = None,
        unsigned_message: Message = None,
        signed_message: Message = None
    ):
        self.identifier = identifier
        self.is_signed = is_signed
        self.message_order = message_order
        self.unsigned_message = unsigned_message
        self.signed_message = signed_message
        self.state_change_id = state_change_id
        self.light_client_payment_id = light_client_payment_id


class DbLightClientProtocolMessage:
    """ Db representation of light client message """
    def __init__(
        self,
        light_client_protocol_message: LigthClientProtocolMessage
    ):
        self.identifier = light_client_protocol_message.identifier
        self.message_order = light_client_protocol_message.message_order
        self.light_client_payment_id = light_client_protocol_message.light_client_payment_id
        self.state_change_id = light_client_protocol_message.state_change_id
        self.unsigned_message = light_client_protocol_message.unsigned_message
        self.signed_message = light_client_protocol_message.signed_message

