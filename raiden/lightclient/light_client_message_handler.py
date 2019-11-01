import string

from raiden.lightclient.lightclientmessages.light_client_payment import LightClientPayment
from raiden.lightclient.lightclientmessages.light_client_protocol_message import LightClientProtocolMessage, \
    DbLightClientProtocolMessage
from raiden.messages import Message, LockedTransfer, SecretRequest, RevealSecret, Secret
from raiden.storage.wal import WriteAheadLog
from typing import List



def build_light_client_protocol_message(identifier: int, message: Message, signed: bool, payment_id: int,
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
        identifier,
        None,
        unsigned_msg,
        signed_msg

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
    def store_light_client_protocol_message(cls, identifier: int, message: Message, signed: bool, payment_id: int,
                                            order: int,
                                            wal: WriteAheadLog):
        return wal.storage.write_light_client_protocol_message(
            message,
            build_light_client_protocol_message(identifier, message, signed,
                                                payment_id, order)
        )

    @classmethod
    def store_light_client_payment(cls, payment: LightClientPayment, wal: WriteAheadLog):
        return wal.storage.write_light_client_payment(payment)

    @classmethod
    def is_light_client_protocol_message_already_stored(cls, payment_id: int, order: int, wal: WriteAheadLog):
        return wal.storage.is_light_client_protocol_message_already_stored(payment_id, order)

    @classmethod
    def is_light_client_protocol_message_already_stored_message_id(cls, message_id: int, payment_id: int, order: int, wal: WriteAheadLog):
        return wal.storage.is_light_client_protocol_message_already_stored_with_message_id(message_id, payment_id, order)

    @classmethod
    def get_light_client_protocol_message_by_identifier(cls, message_identifier: int, wal: WriteAheadLog):
        message = wal.storage.get_light_client_protocol_message_by_identifier(message_identifier)

        return LightClientProtocolMessage(message[3] is not None, message[1], message[5], message[0], message[4], message[2], message[3])

    @staticmethod
    def get_order_principal(messagetype: string):
        switcher = {
            LockedTransfer.__name__: 0,
            SecretRequest.__name__: 5,
            RevealSecret.__name__: 9,
        }
        return switcher.get(messagetype, -1)

    @staticmethod
    def get_order_for_ack(ack_parent_type: string, ack_type: string):
        switcher_processed = {
            LockedTransfer.__name__: 3,
            SecretRequest.__name__: 6,
            RevealSecret.__name__: 10,
            Secret.__name__: 13,
        }
        switcher_delivered = {
            LockedTransfer.__name__: 2,
            RevealSecret.__name__: 8,
            Secret.__name__: 12,
        }
        if ack_type.lower() == "processed":
            return switcher_processed.get(ack_parent_type, -1)
        else:
            return switcher_delivered.get(ack_parent_type, -1)

    @classmethod
    def exists_payment(cls, payment_id: int, wal: WriteAheadLog):
        return wal.storage.exists_payment(payment_id)

