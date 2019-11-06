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
    def get_light_client_messages(cls, from_message: int, wal: WriteAheadLog):
        messages = wal.storage.get_light_client_messages(from_message)
        result: List[LightClientProtocolMessage] = []
        for message in messages:
            signed = message[0]
            order = message[1]
            payment_id = message[2]
            unsigned_msg = message[3]
            signed_msg = message[4]
            identifier = message[5]
            result.append(
                LightClientProtocolMessage(signed, order, payment_id, identifier, unsigned_msg, signed_msg))
        return result

    @classmethod
    def apply_message_order_filter(cls, message: LightClientProtocolMessage, msg_order: int) -> bool:
        return message.message_order >= msg_order

    @classmethod
    def get_light_client_payment(cls, payment_id, wal: WriteAheadLog):
        payment = wal.storage.get_light_client_payment(payment_id)
        if payment:
            payment = LightClientPayment(payment[1], payment[2], payment[3], payment[4], payment[5],
                                         payment[6], payment[7], payment[0])
        return payment

    @classmethod
    def is_get_messages_request_valid(cls, message_request: dict):
        payment_ids = list(message_request.keys())
        msg_orders = list(message_request.values())
        valid_payment_ids = len(payment_ids) > 0
        valid_msg_orders = len(msg_orders) > 0
        if not valid_msg_orders or not valid_payment_ids:
            return False
        else:
            for payment_id in payment_ids:
                if type(payment_id) is not str:
                    return False
            for message_order in msg_orders:
                if type(message_order) is not int:
                    return False
        return True

