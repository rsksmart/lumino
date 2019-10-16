from raiden.lightclient.lightclientmessages.light_client_payment import LightClientPayment
from raiden.lightclient.lightclientmessages.light_client_protocol_message import LightClientProtocolMessage, \
    DbLightClientProtocolMessage
from raiden.messages import Message
from raiden.storage.wal import WriteAheadLog
from typing import List


def build_light_client_protocol_message(message: Message, signed: bool, payment_id: int,
                                        order: int) -> LightClientProtocolMessage:
    if signed:
        signed_msg = message
        unsigned_msg = None
    else:
        signed_msg = None
        unsigned_msg = message
    return LightClientProtocolMessage(
        signed,
        order,
        payment_id,
        None,
        unsigned_msg,
        signed_msg,
        None

    )


class LightClientMessageHandler:

    @classmethod
    def store_light_client_protocol_messages(cls, messages: List[Message], wal: WriteAheadLog):
        protocol_messages = list(map(build_light_client_protocol_message, messages))
        assert len(messages) == len(protocol_messages), "Light client protocol message persist error"
        to_store = []
        for msg_dto in protocol_messages:
            to_store.append(DbLightClientProtocolMessage(msg_dto))
        return wal.storage.write_light_client_protocol_messages(to_store)

    @classmethod
    def store_light_client_protocol_message(cls, message: Message, signed: bool, payment_id: int, order: int,
                                            wal: WriteAheadLog):
        return wal.storage.write_light_client_protocol_message(
            message,
            build_light_client_protocol_message(message, signed,
                                                payment_id, order)
        )

    @classmethod
    def store_light_client_payment(cls, payment: LightClientPayment, wal: WriteAheadLog):
        return wal.storage.write_light_client_payment(payment)

    @classmethod
    def store_light_client_payment(cls, payment: LightClientPayment, wal: WriteAheadLog):
        return wal.storage.write_light_client_payment(payment)

    @classmethod
    def is_light_client_protocol_message_already_stored(cls, payment_id: int, order: int, wal: WriteAheadLog):
        return wal.storage.is_light_client_protocol_message_already_stored(payment_id, order)

