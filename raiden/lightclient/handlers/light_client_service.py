from eth_utils.typing import ChecksumAddress

from raiden.lightclient.models.client_model import ClientModel, ClientType
from raiden.lightclient.lightclientmessages.hub_response_message import HubResponseMessage
from raiden.lightclient.models.light_client_payment import LightClientPayment
from raiden.lightclient.models.light_client_protocol_message import LightClientProtocolMessage, LightClientProtocolMessageType
from raiden.lightclient.lightclientmessages.payment_hub_message import PaymentHubMessage
from raiden.storage.sqlite import SerializedSQLiteStorage
from raiden.storage.wal import WriteAheadLog
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
    def get_light_client_messages(cls, from_message: int, light_client: ChecksumAddress, wal: WriteAheadLog):
        messages = wal.storage.get_light_client_messages(from_message, light_client)
        result: List[HubResponseMessage] = []
        for message in messages:
            signed = message[0]
            order = message[1]
            payment_id = message[2]
            unsigned_msg = message[3]
            signed_msg = message[4]
            internal_identifier = message[6]
            message_type = LightClientProtocolMessageType[message[7]]
            message = signed_msg if signed_msg is not None else unsigned_msg
            payment_hub_message = PaymentHubMessage(payment_id=payment_id,
                                                    message_order=order,
                                                    message=message, is_signed=signed)
            hub_message = HubResponseMessage(internal_identifier, message_type, payment_hub_message)
            result.append(hub_message)
        return result

    @classmethod
    def apply_message_order_filter(cls, message: LightClientProtocolMessage, msg_order: int) -> bool:
        return message.message_order >= msg_order

    @classmethod
    def get_light_client_payment(cls, payment_id, storage: SerializedSQLiteStorage):
        payment = storage.get_light_client_payment(payment_id)
        if payment:
            payment = LightClientPayment(payment[1], payment[2], payment[3], payment[4], int(payment[5]),
                                         payment[6], payment[7], payment[0])
        return payment
