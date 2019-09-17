from eth_utils.typing import ChecksumAddress

from raiden.lightclient.lightclientmessages.light_client_payment import LightClientPayment
from raiden.lightclient.lightclientmessages.light_client_protocol_message import DbLightClientProtocolMessage, \
    LightClientProtocolMessage
from raiden.storage.wal import WriteAheadLog
from .client_model import ClientModel, ClientType
from raiden.utils.typing import List, Optional


class LightClientService:

    @classmethod
    def get_light_clients_data(cls, wal: WriteAheadLog) -> List[ClientModel]:
        light_clients = wal.storage.query_clients(str(ClientType.LIGHT.value))
        result: List[ClientModel] = []
        if light_clients is not None and light_clients:
            result = [ClientModel(lc[0], lc[1], lc[2], lc[3]) for lc in light_clients]
        return result

    @classmethod
    def is_handled_lc(cls, client_address: ChecksumAddress, wal: WriteAheadLog) -> bool:
        light_clients: List[ClientModel] = cls.get_light_clients_data(wal)
        for lc in light_clients:
            if lc.address == client_address:
                return True
        return False

    @classmethod
    def get_by_api_key(cls, api_key, wal: WriteAheadLog) -> Optional[ClientModel]:
        result = None
        lc = wal.storage.query_client_by_api_key(api_key)
        if lc:
            result = ClientModel(lc[0], lc[1], lc[2], lc[3])
        return result

    @classmethod
    def get_light_client_messages(cls, payment_id, message_order, wal: WriteAheadLog):
        messages = wal.storage.get_light_client_messages(payment_id, message_order)
        result: List[LightClientProtocolMessage] = []
        for message in messages:
            result.append(
                LightClientProtocolMessage(message[0], message[1], message[2], message[3], message[4], message[5],
                                           message[6]))
        return result

    @classmethod
    def get_light_client_payment(cls, payment_id, wal: WriteAheadLog):
        payment = wal.storage.get_light_client_payment(payment_id)
        if payment:
            payment = LightClientPayment(payment[1], payment[2], payment[3], payment[4], payment[5],
                                      payment[6], payment[7], payment[8], payment[0])
        return payment
