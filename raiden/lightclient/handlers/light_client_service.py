import os
from binascii import hexlify

from ecies import encrypt
from eth_utils import to_checksum_address
from eth_utils.typing import ChecksumAddress

from raiden.lightclient.lightclientmessages.hub_response_message import HubResponseMessage
from raiden.lightclient.lightclientmessages.payment_hub_message import PaymentHubMessage
from raiden.lightclient.models.client_model import ClientModel, ClientType
from raiden.lightclient.models.light_client_payment import LightClientPayment
from raiden.lightclient.models.light_client_protocol_message import LightClientProtocolMessage, \
    LightClientProtocolMessageType
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
            payment = LightClientPayment(payment[2], payment[3], payment[4], int(payment[5]), payment[6],
                                         payment[7], payment[0], payment[1])
        return payment

    @classmethod
    def store_matrix_light_client(cls,
                                  address,
                                  signed_password,
                                  server_name,
                                  signed_display_name,
                                  signed_seed_retry,
                                  storage,
                                  pubhex
                                  ):

        address = to_checksum_address(address)

        light_client = storage.get_light_client(address)

        encrypt_signed_password = encrypt(pubhex, signed_password.encode())
        encrypt_signed_display_name = encrypt(pubhex, signed_display_name.encode())
        encrypt_signed_seed_retry = encrypt(pubhex, signed_seed_retry.encode())

        if light_client is None:

            api_key = hexlify(os.urandom(20))
            api_key = api_key.decode("utf-8")
            # Check for limit light client
            result = storage.save_light_client(
                api_key=api_key,
                address=address,
                encrypt_signed_password=encrypt_signed_password.hex(),
                encrypt_signed_display_name=encrypt_signed_display_name.hex(),
                encrypt_signed_seed_retry=encrypt_signed_seed_retry.hex(),
                current_server_name=server_name,
                pending_for_deletion=0
            )

            if result > 0:
                result = {"address": address,
                          "encrypt_signed_password": encrypt_signed_password.hex(),
                          "encrypt_signed_display_name": encrypt_signed_display_name.hex(),
                          "api_key": api_key,
                          "encrypt_signed_seed_retry": encrypt_signed_seed_retry.hex(),
                          "message": "successfully registered",
                          "result_code": 200}
            else:
                result = {"message": "An unexpected error has occurred.",
                          "result_code": 500}
        else:
            result = {"address": address,
                      "encrypt_signed_password": encrypt_signed_password.hex(),
                      "encrypt_signed_display_name": encrypt_signed_display_name.hex(),
                      "api_key": light_client['api_key'],
                      "encrypt_signed_seed_retry": encrypt_signed_seed_retry.hex(),
                      "message": "Already registered",
                      "result_code": 409}

        return result

    @classmethod
    def store_rif_comms_light_client(cls, address, storage):
        address = to_checksum_address(address)

        api_key = hexlify(os.urandom(20))
        api_key = api_key.decode("utf-8")

        light_client = storage.get_light_client(address)

        if light_client is None:
            result = storage.save_light_client(
                api_key=api_key,
                address=address,
                encrypt_signed_password=None,
                encrypt_signed_display_name=None,
                encrypt_signed_seed_retry=None,
                current_server_name=None,
                pending_for_deletion=0
            )
            if result > 0:
                return {"address": address,
                        "message": "successfully registered",
                        "api_key": api_key,
                        "result_code": 200}
            else:
                return {"message": "An unexpected error has occurred.",
                        "result_code": 500}
        else:
            return {"address": address,
                    "api_key": light_client['api_key'],
                    "message": "Already registered",
                    "result_code": 409}
