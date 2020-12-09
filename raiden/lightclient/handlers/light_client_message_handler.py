import json
import string
from typing import Any

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
from raiden.utils.typing import AddressHex, SignedTransaction, Address


def build_light_client_protocol_message(identifier: int,
                                        message: Message,
                                        signed: bool,
                                        payment_id: int,
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
        is_signed=signed,
        message_order=order,
        light_client_payment_id=payment_id,
        identifier=identifier,
        message_type=message_type,
        unsigned_message=unsigned_msg,
        signed_message=signed_msg,
        internal_msg_identifier=None,
        light_client_address=light_client_address
    )


class LightClientMessageHandler:
    log = structlog.get_logger(__name__)  # pylint: disable=invalid-name

    @classmethod
    def store_light_client_protocol_message(cls,
                                            identifier: int,
                                            message: Message,
                                            signed: bool,
                                            light_client_address: AddressHex,
                                            order: int,
                                            message_type: LightClientProtocolMessageType,
                                            wal: WriteAheadLog,
                                            payment_id: int = None):
        return wal.storage.write_light_client_protocol_message(
            new_message=message,
            msg_dto=build_light_client_protocol_message(identifier=identifier,
                                                        message=message,
                                                        signed=signed,
                                                        payment_id=payment_id,
                                                        order=order,
                                                        message_type=message_type,
                                                        light_client_address=light_client_address)
        )

    @classmethod
    def update_offchain_light_client_protocol_message_set_signed_message(
        cls, message: Message,
        payment_id: int,
        order: int,
        message_type: LightClientProtocolMessageType,
        light_client_address: AddressHex,
        wal: WriteAheadLog
    ):
        return wal.storage.update_offchain_light_client_protocol_message_set_signed_message(
            payment_id=payment_id,
            msg_order=order,
            signed_message=message,
            message_type=str(message_type.value),
            light_client_address=light_client_address
        )

    @classmethod
    def update_onchain_light_client_protocol_message_set_signed_transaction(
        cls,
        internal_msg_identifier: int,
        signed_message: "SignedTransaction",
        wal: WriteAheadLog
    ):
        return wal.storage.update_onchain_light_client_protocol_message_set_signed_transaction(
            internal_msg_identifier=internal_msg_identifier,
            signed_message=signed_message
        )

    @classmethod
    def store_light_client_payment(cls,
                                   payment: LightClientPayment,
                                   storage: SerializedSQLiteStorage):
        exists_payment = storage.get_light_client_payment(payment.payment_id)
        if not exists_payment:
            storage.write_light_client_payment(payment)

    @classmethod
    def update_light_client_payment_status(cls,
                                           payment_id: int,
                                           status: LightClientPaymentStatus,
                                           storage: SerializedSQLiteStorage):
        exists_payment = storage.get_light_client_payment(payment_id)
        if exists_payment:
            storage.update_light_client_payment_status(light_client_payment_id=payment_id, status=status)

    @classmethod
    def get_message_for_payment(cls,
                                message_id: int,
                                light_client_address: AddressHex,
                                payment_id: int,
                                order: int,
                                message_type: LightClientProtocolMessageType,
                                message_protocol_type: str,
                                wal: WriteAheadLog):
        return cls.map_message_from_result(wal.storage.get_message_for_payment(
            message_id=message_id,
            payment_id=payment_id,
            order=order,
            message_type=str(message_type.value),
            message_protocol_type=message_protocol_type,
            light_client_address=light_client_address
        ))

    @classmethod
    def get_message_by_content(cls,
                               light_client_address: AddressHex,
                               message_type: LightClientProtocolMessageType,
                               message: Message,
                               wal: WriteAheadLog):

        if message_type and light_client_address and message:
            return cls.map_message_from_result(wal.storage.get_message_by_content(
                light_client_address=light_client_address,
                message_type=message_type.value,
                message=message
            ))
        return None

    @classmethod
    def get_message_for_order_and_address(cls,
                                          message_id: int,
                                          payment_id: int,
                                          order: int,
                                          light_client_address: AddressHex,
                                          wal: WriteAheadLog):
        return cls.map_message_from_result(wal.storage.get_message_for_order_and_address(
            message_id=message_id,
            payment_id=payment_id,
            order=order,
            light_client_address=light_client_address
        ))

    @classmethod
    def get_message_by_identifier_for_lc(cls,
                                         message_identifier: int,
                                         light_client_address: AddressHex,
                                         wal: WriteAheadLog):
        return cls.map_message_from_result(wal.storage.get_message_by_identifier_for_lc(
            identifier=message_identifier,
            light_client_address=light_client_address
        ))

    @classmethod
    def get_message_by_internal_identifier(cls,
                                           internal_msg_identifier: int,
                                           wal: WriteAheadLog):
        return cls.map_message_from_result(wal.storage.get_message_by_internal_identifier(internal_msg_identifier))

    @classmethod
    def map_message_from_result(cls, result: Any) -> Any:
        """
            Map the result from a query for protocol message to the object class, it assumes that the result
            comes from a sql query with this order:
            SELECT identifier,
                   message_order,
                   unsigned_message,
                   signed_message,
                   light_client_payment_id,
                   message_type,
                   light_client_address,
                   internal_msg_identifier
            FROM light_client_protocol_message

            Returns the mapped LightClientProtocolMessage object or None if result is None.
        """
        if result:
            return LightClientProtocolMessage(identifier=result[0],
                                              message_order=result[1],
                                              unsigned_message=result[2],
                                              signed_message=result[3],
                                              light_client_payment_id=result[4],
                                              message_type=result[5],
                                              light_client_address=result[6],
                                              internal_msg_identifier=result[7],
                                              is_signed=result[3] is not None)
        return None

    @classmethod
    def get_light_client_payment_locked_transfer(cls,
                                                 payment_identifier: int,
                                                 light_client_address: AddressHex,
                                                 wal: WriteAheadLog):
        return cls.map_message_from_result(wal.storage.get_light_client_payment_locked_transfer(
            payment_identifier=payment_identifier,
            light_client_address=light_client_address
        ))

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
    def store_lc_processed(cls, message: Processed, light_client_address: AddressHex, wal: WriteAheadLog):
        # If exists for that payment, the same message by the order, then discard it.
        message_identifier = message.message_identifier
        # get first principal message by message identifier
        protocol_message = LightClientMessageHandler.get_message_by_identifier_for_lc(
            message_identifier=message_identifier,
            light_client_address=light_client_address,
            wal=wal
        )
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
            exists = LightClientMessageHandler.get_message_for_order_and_address(
                message_id=message_identifier,
                payment_id=protocol_message.light_client_payment_id,
                order=order,
                light_client_address=light_client_address,
                wal=wal
            )
            if not exists:
                LightClientMessageHandler.store_light_client_protocol_message(
                    identifier=message_identifier,
                    message=message,
                    signed=True,
                    light_client_address=light_client_address,
                    order=order,
                    message_type=message_type,
                    wal=wal,
                    payment_id=protocol_message.light_client_payment_id
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
    def store_lc_delivered(cls,
                           message: Delivered,
                           light_client_address: AddressHex,
                           wal: WriteAheadLog):
        # If exists for that payment, the same message by the order, then discard it.
        message_identifier = message.delivered_message_identifier
        # get first by message identifier
        protocol_message = LightClientMessageHandler.get_message_by_identifier_for_lc(
            message_identifier=message_identifier,
            light_client_address=light_client_address,
            wal=wal
        )
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
                payment_identifier=protocol_message.light_client_payment_id,
                light_client_address=light_client_address,
                wal=wal
            )
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
            exists = LightClientMessageHandler.get_message_for_order_and_address(
                message_id=message_identifier,
                payment_id=protocol_message.light_client_payment_id,
                order=order,
                light_client_address=light_client_address,
                wal=wal
            )
            if not exists:
                LightClientMessageHandler.store_light_client_protocol_message(
                    identifier=message_identifier,
                    message=message,
                    signed=True,
                    light_client_address=light_client_address,
                    order=order,
                    message_type=message_type,
                    wal=wal,
                    payment_id=protocol_message.light_client_payment_id)
            else:
                cls.log.info("Message for lc already received, ignoring db storage")

    @classmethod
    def store_update_non_closing_balance_proof(cls, non_closing_balance_proof_data: LightClientNonClosingBalanceProof,
                                               storage: SerializedSQLiteStorage):
        return storage.write_light_client_non_closing_balance_proof(non_closing_balance_proof_data)

    @classmethod
    def get_latest_light_client_non_closing_balance_proof(cls, channel_id: int, non_closing_participant: Address, storage: SerializedSQLiteStorage):
        latest_update_balance_proof_data = storage.get_latest_light_client_non_closing_balance_proof(channel_id, non_closing_participant)
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
