import json
import string

import structlog
from eth_utils import to_checksum_address

from raiden.lightclient.lightclientmessages.light_client_non_closing_balance_proof import \
    LightClientNonClosingBalanceProof
from raiden.lightclient.models.light_client_payment import LightClientPayment, LightClientPaymentStatus
from raiden.lightclient.models.light_client_protocol_message import LightClientProtocolMessage, \
    LightClientProtocolMessageType
from raiden.messages import Message, LockedTransfer, SecretRequest, RevealSecret, Secret, Processed, Delivered, Unlock, \
    LockExpired
from raiden.storage.sqlite import SerializedSQLiteStorage
from raiden.storage.wal import WriteAheadLog
from raiden.utils.typing import AddressHex, SignedTransaction, MessageID


def build_light_client_protocol_message(identifier: int, message: Message, signed: bool, payment_id: int,
                                        order: int,
                                        message_type: LightClientProtocolMessageType,
                                        light_client_address: AddressHex) -> LightClientProtocolMessage:
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
        message_type,
        unsigned_msg,
        signed_msg,
        None,
        light_client_address
    )


class LightClientMessageHandler:
    log = structlog.get_logger(__name__)  # pylint: disable=invalid-name

    @classmethod
    def store_light_client_protocol_message(cls, identifier: int, message: Message, signed: bool,
                                            light_client_address: AddressHex, order: int,
                                            message_type: LightClientProtocolMessageType, wal: WriteAheadLog,
                                            payment_id: int = None):
        return wal.storage.write_light_client_protocol_message(
            message,
            build_light_client_protocol_message(identifier, message, signed,
                                                payment_id, order, message_type, light_client_address)
        )

    @classmethod
    def update_offchain_light_client_protocol_message_set_signed_message(
        cls, message: Message,
        payment_id: int,
        order: int,
        message_type: LightClientProtocolMessageType,
        wal: WriteAheadLog
    ):
        return wal.storage\
            .update_offchain_light_client_protocol_message_set_signed_message(payment_id,
                                                                              order,
                                                                              message,
                                                                              str(message_type.value))

    @classmethod
    def update_stored_msg_set_signed_tx_by_message_id(
        cls, message_id: MessageID, signed_tx: SignedTransaction, wal: WriteAheadLog
    ):
        return wal.storage.update_stored_msg_set_signed_tx_by_message_id(signed_tx, message_id)

    @classmethod
    def store_light_client_payment(cls, payment: LightClientPayment, storage: SerializedSQLiteStorage):
        exists_payment = storage.get_light_client_payment(payment.payment_id)
        if not exists_payment:
            storage.write_light_client_payment(payment)

    @classmethod
    def update_light_client_payment_status(cls, payment_id: int, status: LightClientPaymentStatus,
                                           storage: SerializedSQLiteStorage):
        exists_payment = storage.get_light_client_payment(payment_id)
        if not exists_payment:
            storage.update_light_client_payment_status(payment_id, status, storage)

    @classmethod
    def is_light_client_protocol_message_already_stored(cls, payment_id: int,
                                                        order: int,
                                                        message_type: LightClientProtocolMessageType,
                                                        message_protocol_type: str,
                                                        wal: WriteAheadLog
                                                        ):
        existing_message = wal.storage.is_light_client_protocol_message_already_stored(payment_id, order,
                                                                                       str(message_type.value),
                                                                                       message_protocol_type)

        if existing_message:
            return LightClientProtocolMessage(existing_message[5] is not None,
                                              existing_message[3],
                                              existing_message[2],
                                              existing_message[1],
                                              existing_message[6],
                                              existing_message[4],
                                              existing_message[5],
                                              existing_message[0],
                                              existing_message[7])
        return existing_message

    @classmethod
    def is_message_already_stored(cls,
                                  light_client_address: AddressHex,
                                  message_type: LightClientProtocolMessageType,
                                  unsigned_message: Message,
                                  wal: WriteAheadLog):

        return message_type and light_client_address and unsigned_message and wal.storage\
            .is_message_already_stored(light_client_address,
                                       message_type.value,
                                       unsigned_message)

    @classmethod
    def is_light_client_protocol_message_already_stored_message_id(cls, message_id: int, payment_id: int, order: int,
                                                                   wal: WriteAheadLog):
        return wal.storage.is_light_client_protocol_message_already_stored_with_message_id(message_id, payment_id,
                                                                                           order)

    @classmethod
    def get_light_client_protocol_message_by_identifier(cls, message_identifier: int, wal: WriteAheadLog):
        message = wal.storage.get_light_client_protocol_message_by_identifier(message_identifier)
        return LightClientProtocolMessage(message[3] is not None,
                                          message[1],
                                          message[4],
                                          message[0],
                                          message[5],
                                          message[2],
                                          message[3],
                                          None,
                                          message[6])

    @classmethod
    def get_light_client_protocol_message_by_internal_identifier(cls, internal_msg_identifier: int, wal: WriteAheadLog):
        message = wal.storage.get_light_client_protocol_message_by_internal_identifier(internal_msg_identifier)
        if message:
            return LightClientProtocolMessage(message[3] is not None,
                                              message[1],
                                              message[4],
                                              message[0],
                                              message[5],
                                              message[2],
                                              message[3],
                                              message[7],
                                              message[6])
        return None

    @classmethod
    def get_light_client_payment_locked_transfer(cls, payment_identifier: int, wal: WriteAheadLog):

        message = wal.storage.get_light_client_payment_locked_transfer(payment_identifier)
        identifier = message[0]
        message_order = message[1]
        unsigned_message = message[3]
        signed_message = message[4]
        payment_id = message[5]
        light_client_address = message[6]

        return LightClientProtocolMessage(signed_message is not None,
                                          message_order,
                                          payment_id,
                                          identifier,
                                          LightClientProtocolMessageType.PaymentSuccessful,
                                          unsigned_message,
                                          signed_message,
                                          None,
                                          light_client_address)

    @staticmethod
    def get_order_for_ack(ack_parent_type: string, ack_type: string, is_received_delivered: bool = False):
        switcher_processed = {
            LockedTransfer.__name__: 3,
            Secret.__name__: 13,
            LockExpired.__name__: 3
        }
        switcher_delivered = {
            LockedTransfer.__name__: 4 if not is_received_delivered else 2,
            RevealSecret.__name__: 10 if not is_received_delivered else 8,
            SecretRequest.__name__: 6,
            Secret.__name__: 14 if not is_received_delivered else 12,
            LockExpired.__name__: 4 if not is_received_delivered else 2,

        }
        if ack_type.lower() == "processed":
            return switcher_processed.get(ack_parent_type, -1)
        else:
            return switcher_delivered.get(ack_parent_type, -1)

    @classmethod
    def exists_payment(cls, payment_id: int, wal: WriteAheadLog):
        return wal.storage.exists_payment(payment_id)

    @classmethod
    def store_lc_processed(cls, message: Processed, wal: WriteAheadLog):
        # If exists for that payment, the same message by the order, then discard it.
        message_identifier = message.message_identifier
        # get first principal message by message identifier
        protocol_message = LightClientMessageHandler.get_light_client_protocol_message_by_identifier(
            message_identifier, wal)
        json_message = None
        if protocol_message.signed_message is None:
            json_message = protocol_message.unsigned_message
        else:
            json_message = protocol_message.signed_message
        json_message = json.loads(json_message)

        # Set message type
        first_message_is_le = protocol_message.message_order == 1 and json_message["type"] == "LockExpired"

        message_type = LightClientProtocolMessageType.PaymentSuccessful
        if first_message_is_le:
            message_type = LightClientProtocolMessageType.PaymentExpired

        order = LightClientMessageHandler.get_order_for_ack(json_message["type"], message.__class__.__name__.lower())
        if order == -1:
            cls.log.error("Unable to find principal message for {} {}: ".format(message.__class__.__name__,
                                                                                message_identifier))
        else:
            exists = LightClientMessageHandler.is_light_client_protocol_message_already_stored_message_id(
                message_identifier, protocol_message.light_client_payment_id, order, wal)
            if not exists:
                LightClientMessageHandler.store_light_client_protocol_message(
                    message_identifier,
                    message,
                    True,
                    protocol_message.light_client_address,
                    order,
                    message_type,
                    wal,
                    protocol_message.light_client_payment_id
                )
            else:
                cls.log.info("Message for lc already received, ignoring db storage")

    @classmethod
    def is_received_delivered(cls, locked_transfer, delivered_sender):
        signed_locked_transfer_message = json.loads(locked_transfer.signed_message)
        unsigned_locked_transfer_message = json.loads(
            locked_transfer.unsigned_message) if locked_transfer.unsigned_message is not None else None
        payment_initiator = signed_locked_transfer_message["initiator"]
        recipient = signed_locked_transfer_message["recipient"]
        target = signed_locked_transfer_message["target"]
        if recipient != target and recipient != payment_initiator and target != payment_initiator:
            # Mediated sent
            return to_checksum_address(delivered_sender) != payment_initiator
        else:
            # Mediated received, normal received, normal sent
            if unsigned_locked_transfer_message is None:
                # Received payment
                return to_checksum_address(delivered_sender) == payment_initiator
            else:
                # Normal sent
                return to_checksum_address(delivered_sender) != payment_initiator

    @classmethod
    def store_lc_delivered(cls, message: Delivered, wal: WriteAheadLog):
        # If exists for that payment, the same message by the order, then discard it.
        message_identifier = message.delivered_message_identifier
        # get first by message identifier
        protocol_message = LightClientMessageHandler.get_light_client_protocol_message_by_identifier(
            message_identifier, wal)
        if protocol_message.signed_message is None:
            json_message = protocol_message.unsigned_message
        else:
            json_message = protocol_message.signed_message

        json_message = json.loads(json_message)

        # Set message type
        first_message_is_lt = protocol_message.message_order == 1 and json_message["type"] == "LockedTransfer"
        first_message_is_le = protocol_message.message_order == 1 and json_message["type"] == "LockExpired"

        message_type = LightClientProtocolMessageType.PaymentSuccessful
        if first_message_is_le:
            message_type = LightClientProtocolMessageType.PaymentExpired

        # Check if message is from initiator or it is a reception
        received_delivered = True
        delivered_sender = message.sender
        if not first_message_is_lt:
            # get lt to get the payment identifier
            locked_transfer = LightClientMessageHandler.get_light_client_payment_locked_transfer(
                protocol_message.light_client_payment_id, wal)
            received_delivered = cls.is_received_delivered(locked_transfer, delivered_sender)
        else:
            # message is the lt
            received_delivered = cls.is_received_delivered(protocol_message, delivered_sender)
        # Get the msg order
        order = LightClientMessageHandler.get_order_for_ack(json_message["type"], message.__class__.__name__.lower(),
                                                            received_delivered)

        # Persist the message
        if order == -1:
            cls.log.error("Unable to find principal message for {} {}: ".format(message.__class__.__name__,
                                                                                message_identifier))
        else:
            exists = LightClientMessageHandler.is_light_client_protocol_message_already_stored_message_id(
                message_identifier, protocol_message.light_client_payment_id, order, wal)
            if not exists:
                LightClientMessageHandler.store_light_client_protocol_message(
                    message_identifier, message, True,
                    protocol_message.light_client_address, order,
                    message_type, wal, protocol_message.light_client_payment_id)
            else:
                cls.log.info("Message for lc already received, ignoring db storage")

    @classmethod
    def store_update_non_closing_balance_proof(cls, non_closing_balance_proof_data: LightClientNonClosingBalanceProof,
                                               storage: SerializedSQLiteStorage):
        return storage.write_light_client_non_closing_balance_proof(non_closing_balance_proof_data)

    @classmethod
    def get_latest_light_client_non_closing_balance_proof(cls, channel_id: int, storage: SerializedSQLiteStorage):
        latest_update_balance_proof_data = storage.get_latest_light_client_non_closing_balance_proof(channel_id)
        if latest_update_balance_proof_data:
            balance_proof_dict = json.loads(latest_update_balance_proof_data[7])
            balance_proof = Unlock.from_dict(balance_proof_dict) \
                if balance_proof_dict["type"] == "Secret" \
                else LockedTransfer.from_dict(balance_proof_dict)
            return LightClientNonClosingBalanceProof(latest_update_balance_proof_data[1],
                                                     latest_update_balance_proof_data[2],
                                                     latest_update_balance_proof_data[3],
                                                     latest_update_balance_proof_data[4],
                                                     latest_update_balance_proof_data[5],
                                                     latest_update_balance_proof_data[6],
                                                     balance_proof,
                                                     latest_update_balance_proof_data[8],
                                                     latest_update_balance_proof_data[0]
                                                     )
        return None
