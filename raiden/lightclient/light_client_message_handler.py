from raiden.lightclient.lightclientmessages.light_client_protocol_message import LigthClientProtocolMessage, \
    DbLightClientProtocolMessage
from raiden.messages import Message
from raiden.storage.wal import WriteAheadLog
from typing import List


def build_light_client_protocol_message(message: Message) -> LigthClientProtocolMessage:
    import random
    return LigthClientProtocolMessage(
        random.randint(1, 10000),
        False,
        2,
        2,
        None,
        message,
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
        wal.storage.write_light_client_protocol_messages(to_store)

    @classmethod
    def store_light_client_protocol_message(cls, message: Message, wal: WriteAheadLog):
        wal.storage.write_light_client_protocol_message(message, build_light_client_protocol_message(message))
