import random
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

import structlog
from eth_utils import to_checksum_address, to_hex, encode_hex, to_canonical_address
from raiden.api.objects import SettlementParameters
from raiden.billing.invoices.handlers.invoice_handler import handle_receive_events_with_payments
from raiden.constants import EMPTY_BALANCE_HASH, EMPTY_HASH, EMPTY_MESSAGE_HASH, EMPTY_SIGNATURE
from raiden.exceptions import ChannelOutdatedError, RaidenUnrecoverableError
from raiden.lightclient.handlers.light_client_message_handler import LightClientMessageHandler
from raiden.lightclient.models.light_client_protocol_message import LightClientProtocolMessageType, \
    LightClientProtocolMessage
from raiden.message_event_convertor import message_from_sendevent
from raiden.messages import RequestRegisterSecret, UnlockLightRequest, SettlementRequiredLightMessage
from raiden.network.proxies.payment_channel import PaymentChannel
from raiden.network.proxies.token_network import TokenNetwork
from raiden.network.resolver.client import reveal_secret_with_resolver
from raiden.transfer import views
from raiden.transfer.architecture import Event
from raiden.transfer.balance_proof import pack_balance_proof_update
from raiden.transfer.channel import get_batch_unlock, get_batch_unlock_gain
from raiden.transfer.events import (
    ContractSendChannelBatchUnlock,
    ContractSendChannelClose,
    ContractSendChannelSettle,
    ContractSendChannelUpdateTransfer,
    ContractSendSecretReveal,
    ContractSendSecretRevealLight,
    EventInvalidReceivedLockedTransfer,
    EventInvalidReceivedLockExpired,
    EventInvalidReceivedTransferRefund,
    EventInvalidReceivedUnlock,
    EventPaymentSentFailed,
    EventPaymentSentSuccess,
    SendProcessed,
    ContractSendChannelUpdateTransferLight,
    ContractSendChannelBatchUnlockLight,
    ContractSendChannelSettleLight
)
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.mediated_transfer.events import (
    EventUnlockClaimFailed,
    EventUnlockClaimSuccess,
    EventUnlockFailed,
    EventUnlockSuccess,
    SendBalanceProof,
    SendLockedTransfer,
    SendLockExpired,
    SendRefundTransfer,
    SendSecretRequest,
    SendSecretReveal,
    SendLockedTransferLight,
    StoreMessageEvent,
    SendSecretRevealLight,
    SendBalanceProofLight,
    SendSecretRequestLight,
    SendLockExpiredLight
)
from raiden.transfer.state import ChainState, message_identifier_from_prng, NettingChannelEndState
from raiden.transfer.unlock import get_channel_state, should_search_events, should_search_state_changes
from raiden.transfer.utils import (
    get_event_with_balance_proof_by_balance_hash,
    get_state_change_with_balance_proof_by_balance_hash,
)
from raiden.transfer.views import get_channelstate_by_token_network_and_partner
from raiden.utils import pex
from raiden.utils.typing import MYPY_ANNOTATION, Address, Nonce, TokenNetworkID, AddressHex, ChannelID, BlockHash
from transport.message import Message as TransportMessage

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.raiden_service import RaidenService

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name
UNEVENTFUL_EVENTS = (
    EventUnlockSuccess,
    EventUnlockClaimFailed,
    EventUnlockClaimSuccess,
    EventInvalidReceivedLockedTransfer,
    EventInvalidReceivedLockExpired,
    EventInvalidReceivedTransferRefund,
    EventInvalidReceivedUnlock,
)


def unlock(
    raiden: "RaidenService",
    payment_channel: PaymentChannel,
    end_state: NettingChannelEndState,
    participant: Address,
    partner: Address,
) -> None:
    merkle_tree_leaves = get_batch_unlock(end_state)

    try:
        payment_channel.unlock(
            participant=participant, partner=partner, merkle_tree_leaves=merkle_tree_leaves
        )
    except ChannelOutdatedError as e:
        log.error(str(e), node=pex(raiden.address))


def unlock_light(raiden: "RaidenService",
                 chain_state: ChainState,
                 channel_unlock_event: ContractSendChannelBatchUnlockLight,
                 participant: Address,
                 partner: Address,
                 end_state: NettingChannelEndState):
    merkle_tree_leaves = get_batch_unlock(end_state)
    leaves_packed = str(encode_hex(b"".join(lock.encoded for lock in merkle_tree_leaves)))

    canonical_identifier: CanonicalIdentifier = channel_unlock_event.canonical_identifier

    token_network = views.get_token_network_by_identifier(chain_state, canonical_identifier.token_network_address)
    message = UnlockLightRequest(
        token_address=token_network.token_address,
        channel_identifier=canonical_identifier.channel_identifier,
        receiver=participant,
        sender=partner,
        merkle_tree_leaves=leaves_packed
    )
    if not LightClientMessageHandler.get_message_by_content(
        light_client_address=channel_unlock_event.client,
        message_type=LightClientProtocolMessageType.UnlockLightRequest,
        message=message,
        wal=raiden.wal
    ):
        LightClientMessageHandler.store_light_client_protocol_message(
            identifier=message_identifier_from_prng(chain_state.pseudo_random_generator),
            signed=False,
            payment_id=0,
            order=0,
            message_type=LightClientProtocolMessageType.UnlockLightRequest,
            wal=raiden.wal,
            light_client_address=channel_unlock_event.client,
            message=message
        )


class EventHandler(ABC):
    @abstractmethod
    def on_raiden_event(self, raiden: "RaidenService", chain_state: ChainState, event: Event):
        pass


class RaidenEventHandler(EventHandler):

    @staticmethod
    def event_from_light_client(chain_state: ChainState, partner_address: AddressHex,
                                canonical_identifier: CanonicalIdentifier):
        return views.get_channelstate_by_canonical_identifier_and_address(chain_state, canonical_identifier,
                                                                          partner_address)

    def on_raiden_event(self, raiden: "RaidenService", chain_state: ChainState, event: Event):
        # pylint: disable=too-many-branches
        if type(event) == SendLockExpired:
            assert isinstance(event, SendLockExpired), MYPY_ANNOTATION
            self.handle_send_lockexpired(raiden, event)
        elif type(event) == SendLockExpiredLight:
            assert isinstance(event, SendLockExpiredLight), MYPY_ANNOTATION
            self.handle_send_lockexpired_light(raiden, event)
        elif type(event) == SendLockedTransfer:
            assert isinstance(event, SendLockedTransfer), MYPY_ANNOTATION
            self.handle_send_lockedtransfer(raiden, event)
        elif type(event) == SendLockedTransferLight:
            assert isinstance(event, SendLockedTransferLight), MYPY_ANNOTATION
            self.handle_send_lockedtransfer_light(raiden, event)
        elif type(event) == SendSecretReveal:
            assert isinstance(event, SendSecretReveal), MYPY_ANNOTATION
            self.handle_send_secretreveal(raiden, event)
        elif type(event) == SendSecretRevealLight:
            assert isinstance(event, SendSecretRevealLight), MYPY_ANNOTATION
            self.handle_send_secretreveal_light(raiden, event)
        elif type(event) == SendBalanceProof:
            assert isinstance(event, SendBalanceProof), MYPY_ANNOTATION
            self.handle_send_balanceproof(raiden, event)
        elif type(event) == SendBalanceProofLight:
            assert isinstance(event, SendBalanceProofLight), MYPY_ANNOTATION
            self.handle_send_balanceproof_light(raiden, event)
        elif type(event) == SendSecretRequest:
            assert isinstance(event, SendSecretRequest), MYPY_ANNOTATION
            self.handle_send_secretrequest(raiden, event)
        elif type(event) == SendSecretRequestLight:
            assert isinstance(event, SendSecretRequestLight), MYPY_ANNOTATION
            self.handle_send_secretrequest_light(raiden, event)
        elif type(event) == SendRefundTransfer:
            assert isinstance(event, SendRefundTransfer), MYPY_ANNOTATION
            self.handle_send_refundtransfer(raiden, event)
        elif type(event) == SendProcessed:
            assert isinstance(event, SendProcessed), MYPY_ANNOTATION
            self.handle_send_processed(raiden, event)
        elif type(event) == EventPaymentSentSuccess:
            assert isinstance(event, EventPaymentSentSuccess), MYPY_ANNOTATION
            self.handle_paymentsentsuccess(raiden, event)
        elif type(event) == EventPaymentSentFailed:
            assert isinstance(event, EventPaymentSentFailed), MYPY_ANNOTATION
            self.handle_paymentsentfailed(raiden, event)
        elif type(event) == EventUnlockFailed:
            assert isinstance(event, EventUnlockFailed), MYPY_ANNOTATION
            self.handle_unlockfailed(raiden, event)
        elif type(event) == ContractSendSecretReveal:
            assert isinstance(event, ContractSendSecretReveal), MYPY_ANNOTATION
            self.handle_contract_send_secretreveal(raiden, event)
        elif type(event) == ContractSendSecretRevealLight:
            assert isinstance(event, ContractSendSecretRevealLight), MYPY_ANNOTATION
            self.handle_contract_send_secretreveal_light(raiden, event)
        elif type(event) == ContractSendChannelClose:
            assert isinstance(event, ContractSendChannelClose), MYPY_ANNOTATION
            self.handle_contract_send_channelclose(raiden, chain_state, event)
        elif type(event) == ContractSendChannelUpdateTransfer:
            assert isinstance(event, ContractSendChannelUpdateTransfer), MYPY_ANNOTATION
            self.handle_contract_send_channelupdate(raiden, event)
        elif type(event) == ContractSendChannelUpdateTransferLight:
            assert isinstance(event, ContractSendChannelUpdateTransferLight), MYPY_ANNOTATION
            self.handle_contract_send_channelupdate_light(raiden, event)
        elif type(event) == ContractSendChannelBatchUnlock:
            assert isinstance(event, ContractSendChannelBatchUnlock), MYPY_ANNOTATION
            self.handle_contract_send_channelunlock(raiden, chain_state, event)
        elif type(event) == ContractSendChannelBatchUnlockLight:
            assert isinstance(event, ContractSendChannelBatchUnlockLight), MYPY_ANNOTATION
            self.handle_contract_send_channelunlock_light(raiden, chain_state, event)
        elif type(event) == ContractSendChannelSettle:
            assert isinstance(event, ContractSendChannelSettle), MYPY_ANNOTATION
            self.handle_contract_send_channelsettle(raiden, event)
        elif type(event) == ContractSendChannelSettleLight:
            assert isinstance(event, ContractSendChannelSettleLight), MYPY_ANNOTATION
            self.handle_contract_send_channel_settle_light(raiden, event)
        elif type(event) == StoreMessageEvent:
            assert isinstance(event, StoreMessageEvent), MYPY_ANNOTATION
            self.handle_store_message(raiden, event)
        elif type(event) in UNEVENTFUL_EVENTS:
            pass
        else:
            log.error("Unknown event", event_type=str(type(event)), node=pex(raiden.address))

    @staticmethod
    def handle_store_message(raiden: "RaidenService", store_message_event: StoreMessageEvent):
        existing_message = RaidenEventHandler.get_existing_lc_message_from_store_event(
            raiden=raiden,
            store_message_event=store_message_event
        )
        if existing_message:
            if not existing_message.is_signed and store_message_event.is_signed:
                # Update messages that were created by the hub and now are received signed by the light client
                LightClientMessageHandler.update_offchain_light_client_protocol_message_set_signed_message(
                    message=store_message_event.message,
                    payment_id=store_message_event.payment_id,
                    order=store_message_event.message_order,
                    message_type=store_message_event.message_type,
                    light_client_address=store_message_event.light_client_address,
                    wal=raiden.wal
                )
            else:
                log.info("Message for lc already received, ignoring db storage")
        else:
            LightClientMessageHandler.store_light_client_protocol_message(
                identifier=store_message_event.message_id,
                message=store_message_event.message,
                signed=store_message_event.is_signed,
                light_client_address=store_message_event.light_client_address,
                order=store_message_event.message_order,
                message_type=store_message_event.message_type,
                wal=raiden.wal,
                payment_id=store_message_event.payment_id
            )

    @staticmethod
    def get_existing_lc_message_from_store_event(raiden: "RaidenService",
                                                 store_message_event: StoreMessageEvent) -> LightClientProtocolMessage:
        existing_message: LightClientProtocolMessage
        if store_message_event.payment_id:
            # payment related message
            existing_message = LightClientMessageHandler.get_message_for_payment(
                message_id=store_message_event.message_id,
                light_client_address=store_message_event.light_client_address,
                payment_id=store_message_event.payment_id,
                order=store_message_event.message_order,
                message_type=store_message_event.message_type,
                message_protocol_type=store_message_event.message.to_dict()["type"],
                wal=raiden.wal
            )
        else:
            existing_message = LightClientMessageHandler.get_message_by_content(
                light_client_address=store_message_event.light_client_address,
                message_type=store_message_event.message_type,
                message=store_message_event.message,
                wal=raiden.wal
            )
        return existing_message

    @staticmethod
    def handle_send_lockexpired(raiden: "RaidenService", send_lock_expired: SendLockExpired):
        lock_expired_message = message_from_sendevent(send_lock_expired)
        raiden.sign(lock_expired_message)
        raiden.transport.full_node.enqueue_message(
            *TransportMessage.wrap(send_lock_expired.queue_identifier, lock_expired_message)
        )

    @staticmethod
    def handle_send_lockexpired_light(raiden: "RaidenService", send_lock_expired: SendLockExpiredLight):
        signed_lock_expired = send_lock_expired.signed_lock_expired
        lc_transport = raiden.transport.get_light_client_transport(signed_lock_expired.sender)
        if lc_transport:
            lc_transport.enqueue_message(
                *TransportMessage.wrap(send_lock_expired.queue_identifier, signed_lock_expired)
            )

    @staticmethod
    def handle_send_lockedtransfer(
        raiden: "RaidenService", send_locked_transfer: SendLockedTransfer
    ):
        mediated_transfer_message = message_from_sendevent(send_locked_transfer)
        raiden.sign(mediated_transfer_message)
        raiden.transport.full_node.enqueue_message(
            *TransportMessage.wrap(send_locked_transfer.queue_identifier, mediated_transfer_message)
        )

    @staticmethod
    def handle_send_lockedtransfer_light(
        raiden: "RaidenService", send_locked_transfer_light: SendLockedTransferLight
    ):
        mediated_transfer_message = send_locked_transfer_light.signed_locked_transfer
        light_client_address = send_locked_transfer_light.signed_locked_transfer.initiator
        light_client_transport = raiden.transport.get_light_client_transport(light_client_address)
        light_client_transport.enqueue_message(
            *TransportMessage.wrap(send_locked_transfer_light.queue_identifier, mediated_transfer_message)
        )

    @staticmethod
    def handle_send_secretreveal(raiden: "RaidenService", reveal_secret_event: SendSecretReveal):
        reveal_secret_message = message_from_sendevent(reveal_secret_event)
        raiden.sign(reveal_secret_message)
        raiden.transport.full_node.enqueue_message(
            *TransportMessage.wrap(reveal_secret_event.queue_identifier, reveal_secret_message)
        )

    @staticmethod
    def handle_send_secretreveal_light(raiden: "RaidenService", reveal_secret_event: SendSecretRevealLight):
        signed_secret_reveal = reveal_secret_event.signed_secret_reveal
        lc_transport = raiden.transport.get_light_client_transport(reveal_secret_event.sender)
        if lc_transport:
            lc_transport.enqueue_message(
                *TransportMessage.wrap(reveal_secret_event.queue_identifier, signed_secret_reveal)
            )

    @staticmethod
    def handle_send_balanceproof(raiden: "RaidenService", balance_proof_event: SendBalanceProof):
        unlock_message = message_from_sendevent(balance_proof_event)
        raiden.sign(unlock_message)
        raiden.transport.full_node.enqueue_message(
            *TransportMessage.wrap(balance_proof_event.queue_identifier, unlock_message)
        )

    @staticmethod
    def handle_send_balanceproof_light(raiden: "RaidenService", balance_proof_event: SendBalanceProofLight):
        unlock_message = message_from_sendevent(balance_proof_event)
        lc_transport = raiden.transport.get_light_client_transport(balance_proof_event.sender)
        if lc_transport:
            lc_transport.enqueue_message(
                *TransportMessage.wrap(balance_proof_event.queue_identifier, unlock_message)
            )

    @staticmethod
    def handle_send_secretrequest(
        raiden: "RaidenService", secret_request_event: SendSecretRequest
    ):
        if reveal_secret_with_resolver(raiden, secret_request_event):
            return

        secret_request_message = message_from_sendevent(secret_request_event)
        raiden.sign(secret_request_message)
        raiden.transport.full_node.enqueue_message(
            *TransportMessage.wrap(secret_request_event.queue_identifier, secret_request_message)
        )

    @staticmethod
    def handle_send_secretrequest_light(
        raiden: "RaidenService", secret_request_event: SendSecretRequestLight
    ):
        secret_request_message = message_from_sendevent(secret_request_event)
        lc_transport = raiden.transport.get_light_client_transport(secret_request_event.sender)
        if lc_transport:
            lc_transport.enqueue_message(
                *TransportMessage.wrap(secret_request_event.queue_identifier, secret_request_message)
            )

    @staticmethod
    def handle_send_refundtransfer(
        raiden: "RaidenService", refund_transfer_event: SendRefundTransfer
    ):
        refund_transfer_message = message_from_sendevent(refund_transfer_event)
        raiden.sign(refund_transfer_message)
        raiden.transport.full_node.enqueue_message(
            *TransportMessage.wrap(refund_transfer_event.queue_identifier, refund_transfer_message)
        )

    @staticmethod
    def handle_send_processed(raiden: "RaidenService", processed_event: SendProcessed):
        processed_message = message_from_sendevent(processed_event)
        raiden.sign(processed_message)
        raiden.transport.full_node.enqueue_message(
            *TransportMessage.wrap(processed_event.queue_identifier, processed_message)
        )

    @staticmethod
    def handle_paymentsentsuccess(
        raiden: "RaidenService", payment_sent_success_event: EventPaymentSentSuccess
    ):

        target = payment_sent_success_event.target
        payment_identifier = payment_sent_success_event.identifier
        payment_status = raiden.targets_to_identifiers_to_statuses[target].pop(payment_identifier)

        handle_receive_events_with_payments(raiden.wal.storage,
                                            payment_status.payment_hash_invoice,
                                            'raiden.transfer.events.EventPaymentSentSuccess',
                                            payment_identifier)

        # With the introduction of the lock we should always get
        # here only once per identifier so payment_status should always exist
        # see: https://github.com/raiden-network/raiden/pull/3191
        payment_status.payment_done.set(payment_sent_success_event.secret)

    @staticmethod
    def handle_paymentsentfailed(
        raiden: "RaidenService", payment_sent_failed_event: EventPaymentSentFailed
    ):
        target = payment_sent_failed_event.target
        payment_identifier = payment_sent_failed_event.identifier
        payment_status = raiden.targets_to_identifiers_to_statuses[target].pop(
            payment_identifier, None
        )
        if payment_status:
            handle_receive_events_with_payments(raiden.wal.storage,
                                                payment_status.payment_hash_invoice,
                                                'raiden.transfer.events.EventPaymentSentFailed',
                                                payment_identifier)

            # In the case of a refund transfer the payment fails earlier
            # but the lock expiration will generate a second
            # EventPaymentSentFailed message which we can ignore here

            payment_status.payment_done.set(False)

    @staticmethod
    def handle_unlockfailed(raiden: "RaidenService", unlock_failed_event: EventUnlockFailed):
        # pylint: disable=unused-argument
        log.error(
            "UnlockFailed!",
            secrethash=pex(unlock_failed_event.secrethash),
            reason=unlock_failed_event.reason,
            node=pex(raiden.address),
        )

    @staticmethod
    def handle_contract_send_secretreveal(
        raiden: "RaidenService", channel_reveal_secret_event: ContractSendSecretReveal
    ):
        raiden.default_secret_registry.register_secret(secret=channel_reveal_secret_event.secret)

    @staticmethod
    def handle_contract_send_secretreveal_light(
        raiden: "RaidenService", channel_reveal_secret_event: ContractSendSecretRevealLight
    ):
        message = RequestRegisterSecret(raiden.default_secret_registry.address)
        existing_message = LightClientMessageHandler.get_message_for_payment(
            message_id=channel_reveal_secret_event.message_id,
            light_client_address=channel_reveal_secret_event.light_client_address,
            payment_id=channel_reveal_secret_event.payment_identifier,
            order=0,
            message_type=LightClientProtocolMessageType.RequestRegisterSecret,
            message_protocol_type=message.to_dict()["type"],
            wal=raiden.wal
        )
        # Do not store the RegisterSecretRequest twice for same payment
        if not existing_message:
            LightClientMessageHandler.store_light_client_protocol_message(
                identifier=channel_reveal_secret_event.message_id,
                message=message,
                signed=False,
                payment_id=channel_reveal_secret_event.payment_identifier,
                light_client_address=channel_reveal_secret_event.light_client_address,
                order=0,
                message_type=LightClientProtocolMessageType.RequestRegisterSecret,
                wal=raiden.wal
            )

    @staticmethod
    def handle_contract_send_channelclose(
        raiden: "RaidenService",
        chain_state: ChainState,
        channel_close_event: ContractSendChannelClose,
    ):
        balance_proof = channel_close_event.balance_proof

        if balance_proof:
            nonce = balance_proof.nonce
            balance_hash = balance_proof.balance_hash
            signature = balance_proof.signature
            message_hash = balance_proof.message_hash

        else:
            nonce = Nonce(0)
            balance_hash = EMPTY_BALANCE_HASH
            signature = EMPTY_SIGNATURE
            message_hash = EMPTY_MESSAGE_HASH

        channel_proxy = raiden.chain.payment_channel(
            creator_address=channel_close_event.our_address,
            canonical_identifier=CanonicalIdentifier(
                chain_identifier=chain_state.chain_id,
                token_network_address=channel_close_event.token_network_identifier,
                channel_identifier=channel_close_event.channel_identifier,
            )
        )

        if channel_close_event.signed_close_tx is None:
            channel_proxy.close(
                nonce=nonce,
                balance_hash=balance_hash,
                additional_hash=message_hash,
                signature=signature,
                block_identifier=channel_close_event.triggered_by_block_hash)
        else:
            channel_proxy.close_light(nonce=nonce,
                                      balance_hash=balance_hash,
                                      additional_hash=message_hash,
                                      signature=signature,
                                      block_identifier=channel_close_event.triggered_by_block_hash,
                                      signed_close_tx=channel_close_event.signed_close_tx)

    @staticmethod
    def handle_contract_send_channelupdate(
        raiden: "RaidenService", channel_update_event: ContractSendChannelUpdateTransfer
    ):
        balance_proof = channel_update_event.balance_proof

        if balance_proof:
            canonical_identifier = balance_proof.canonical_identifier
            channel = raiden.chain.payment_channel(
                creator_address=channel_update_event.our_address,
                canonical_identifier=canonical_identifier
            )

            non_closing_data = pack_balance_proof_update(
                nonce=balance_proof.nonce,
                balance_hash=balance_proof.balance_hash,
                additional_hash=balance_proof.message_hash,
                canonical_identifier=canonical_identifier,
                partner_signature=balance_proof.signature,
            )
            our_signature = raiden.signer.sign(data=non_closing_data)

            channel.update_transfer(
                nonce=balance_proof.nonce,
                balance_hash=balance_proof.balance_hash,
                additional_hash=balance_proof.message_hash,
                partner_signature=balance_proof.signature,
                signature=our_signature,
                block_identifier=channel_update_event.triggered_by_block_hash,
            )

    @staticmethod
    def handle_contract_send_channelupdate_light(
        raiden: "RaidenService", channel_update_event: ContractSendChannelUpdateTransferLight
    ):
        balance_proof = channel_update_event.balance_proof

        # checking that this balance proof exists on the database
        db_balance_proof = raiden.wal.storage.get_latest_light_client_non_closing_balance_proof(
            channel_id=balance_proof.channel_identifier,
            non_closing_participant=channel_update_event.lc_address
        )

        if db_balance_proof:
            canonical_identifier = balance_proof.canonical_identifier
            channel = raiden.chain.payment_channel(creator_address=channel_update_event.lc_address,
                                                   canonical_identifier=canonical_identifier)
            channel.update_transfer_light(
                nonce=balance_proof.nonce,
                balance_hash=balance_proof.balance_hash,
                additional_hash=balance_proof.message_hash,
                partner_signature=balance_proof.signature,
                signature=channel_update_event.lc_bp_signature,
                block_identifier=channel_update_event.triggered_by_block_hash,
                raiden=raiden
            )

    @staticmethod
    def handle_contract_send_channelunlock(
        raiden: "RaidenService",
        chain_state: ChainState,
        channel_unlock_event: ContractSendChannelBatchUnlock,
    ):
        assert raiden.wal, "The Raiden Service must be initialize to handle events"

        canonical_identifier = channel_unlock_event.canonical_identifier
        token_network_identifier = canonical_identifier.token_network_address
        participant = channel_unlock_event.participant

        payment_channel: PaymentChannel = raiden.chain.payment_channel(
            creator_address=participant,
            canonical_identifier=canonical_identifier
        )

        channel_state = get_channelstate_by_token_network_and_partner(
            chain_state=chain_state,
            token_network_id=TokenNetworkID(token_network_identifier),
            creator_address=raiden.address,
            partner_address=participant,
        )

        if not channel_state:
            # channel was cleaned up already due to an unlock
            raise RaidenUnrecoverableError(
                f"Failed to find channel state with partner:"
                f"{to_checksum_address(participant)}, token_network:pex(token_network_identifier)"
            )

        our_address = channel_state.our_state.address
        our_locksroot = channel_state.our_state.onchain_locksroot

        partner_address = channel_state.partner_state.address
        partner_locksroot = channel_state.partner_state.onchain_locksroot

        # we want to unlock because there are on-chain unlocked locks
        search_events = our_locksroot != EMPTY_HASH
        # we want to unlock, because there are unlocked/unclaimed locks
        search_state_changes = partner_locksroot != EMPTY_HASH

        if not search_events and not search_state_changes:
            # In the case that someone else sent the unlock we do nothing
            # Check https://github.com/raiden-network/raiden/issues/3152
            # for more details
            log.warning(
                "Onchain unlock already mined",
                canonical_identifier=canonical_identifier,
                channel_identifier=canonical_identifier.channel_identifier,
                participant=to_checksum_address(participant),
            )
            return

        if search_state_changes:
            gain = get_batch_unlock_gain(channel_state)
            if gain.from_partner_locks > 0:
                unlock(
                    raiden=raiden,
                    payment_channel=payment_channel,
                    end_state=channel_state.partner_state,
                    participant=our_address,
                    partner=partner_address,
                )

        if search_events:
            gain = get_batch_unlock_gain(channel_state)
            if gain.from_our_locks > 0:
                unlock(
                    raiden=raiden,
                    payment_channel=payment_channel,
                    end_state=channel_state.our_state,
                    participant=partner_address,
                    partner=our_address,
                )

    @staticmethod
    def handle_contract_send_channelunlock_light(
        raiden: "RaidenService",
        chain_state: ChainState,
        channel_unlock_event: ContractSendChannelBatchUnlockLight,
    ):
        channel_state = get_channel_state(
            raiden=raiden,
            chain_state=chain_state,
            canonical_identifier=channel_unlock_event.canonical_identifier,
            participant=channel_unlock_event.participant,
            our_address=channel_unlock_event.client)
        if should_search_state_changes(channel_state):
            gain = get_batch_unlock_gain(channel_state)
            if gain.from_partner_locks > 0:
                unlock_light(
                    raiden=raiden,
                    chain_state=chain_state,
                    channel_unlock_event=channel_unlock_event,
                    participant=channel_state.our_state.address,
                    partner=channel_state.partner_state.address,
                    end_state=channel_state.partner_state
                )
        if should_search_events(channel_state):
            gain = get_batch_unlock_gain(channel_state)
            if gain.from_our_locks > 0:
                unlock_light(
                    raiden=raiden,
                    chain_state=chain_state,
                    channel_unlock_event=channel_unlock_event,
                    participant=channel_state.partner_state.address,
                    partner=channel_state.our_state.address,
                    end_state=channel_state.our_state
                )

    @staticmethod
    def handle_contract_send_channelsettle(
        raiden: "RaidenService", channel_settle_event: ContractSendChannelSettle
    ):
        """ Handles settlement for normal node. """

        our_address = channel_settle_event.channel_state.our_state.address
        settlement_parameters = RaidenEventHandler.process_data_and_get_settlement_parameters(
            raiden,
            our_address,
            channel_settle_event.token_network_identifier,
            channel_settle_event.channel_identifier,
            channel_settle_event.triggered_by_block_hash
        )

        canonical_identifier = CanonicalIdentifier(
            chain_identifier=raiden.chain.network_id,
            token_network_address=channel_settle_event.token_network_identifier,
            channel_identifier=channel_settle_event.channel_identifier,
        )

        payment_channel: PaymentChannel = raiden.chain.payment_channel(
            creator_address=our_address,
            canonical_identifier=canonical_identifier
        )

        payment_channel.settle(
            transferred_amount=settlement_parameters.transferred_amount,
            locked_amount=settlement_parameters.locked_amount,
            locksroot=settlement_parameters.locksroot,
            partner_transferred_amount=settlement_parameters.partner_transferred_amount,
            partner_locked_amount=settlement_parameters.partner_locked_amount,
            partner_locksroot=settlement_parameters.partner_locksroot,
            block_identifier=settlement_parameters.block_identifier,
        )

    @staticmethod
    def handle_contract_send_channel_settle_light(raiden: "RaidenService",
                                                  channel_settle_light_event: ContractSendChannelSettleLight):
        """ Store a message for the LC with SettlementRequired type to handle settlement for LC on hub mode. """

        log.debug("Handling channel settle light")

        our_address = channel_settle_light_event.channel_state.our_state.address
        settlement_parameters = RaidenEventHandler.process_data_and_get_settlement_parameters(
            raiden,
            our_address,
            channel_settle_light_event.token_network_identifier,
            channel_settle_light_event.channel_identifier,
            channel_settle_light_event.triggered_by_block_hash
        )

        canonical_identifier = CanonicalIdentifier(
            chain_identifier=raiden.chain.network_id,
            token_network_address=channel_settle_light_event.token_network_identifier,
            channel_identifier=channel_settle_light_event.channel_identifier
        )

        payment_channel: PaymentChannel = raiden.chain.payment_channel(
            creator_address=our_address,
            canonical_identifier=canonical_identifier
        )

        pseudo_random_generator = random.Random()

        message_identifier = message_identifier_from_prng(pseudo_random_generator)

        # and now find out our maximum and the partner maximum to compare and figure out which is higher
        our_maximum = settlement_parameters.transferred_amount + settlement_parameters.locked_amount
        partner_maximum = settlement_parameters.partner_transferred_amount + settlement_parameters.partner_locked_amount

        # The second participant transferred + locked amount must be higher by contract requirement
        our_bp_is_larger = our_maximum > partner_maximum
        if our_bp_is_larger:
            message = SettlementRequiredLightMessage(
                channel_identifier=channel_settle_light_event.channel_identifier,
                channel_network_identifier=channel_settle_light_event.token_network_identifier,
                participant1=payment_channel.participant2,
                participant1_transferred_amount=settlement_parameters.partner_transferred_amount,
                participant1_locked_amount=settlement_parameters.partner_locked_amount,
                participant1_locksroot=settlement_parameters.partner_locksroot,
                participant2=payment_channel.participant1,
                participant2_transferred_amount=settlement_parameters.transferred_amount,
                participant2_locked_amount=settlement_parameters.locked_amount,
                participant2_locksroot=settlement_parameters.locksroot)
        else:
            message = SettlementRequiredLightMessage(
                channel_identifier=channel_settle_light_event.channel_identifier,
                channel_network_identifier=channel_settle_light_event.token_network_identifier,
                participant1=payment_channel.participant1,
                participant1_transferred_amount=settlement_parameters.transferred_amount,
                participant1_locked_amount=settlement_parameters.locked_amount,
                participant1_locksroot=settlement_parameters.locksroot,
                participant2=payment_channel.participant2,
                participant2_transferred_amount=settlement_parameters.partner_transferred_amount,
                participant2_locked_amount=settlement_parameters.partner_locked_amount,
                participant2_locksroot=settlement_parameters.partner_locksroot)

        log.debug("Storing light client message to require settle")

        message_already_stored = LightClientMessageHandler.get_message_by_content(
            light_client_address=payment_channel.participant1,
            message_type=LightClientProtocolMessageType.SettlementRequired,
            message=message,
            wal=raiden.wal)

        if message_already_stored:
            log.debug(
                "Skipping storing light client settle message "
                "for {} with type {} since already exists in database".format(
                    payment_channel.participant1.hex(),
                    str(LightClientProtocolMessageType.SettlementRequired)))
        else:
            LightClientMessageHandler \
                .store_light_client_protocol_message(identifier=message_identifier,
                                                     message=message,
                                                     signed=False,
                                                     payment_id=None,
                                                     light_client_address=payment_channel.participant1,
                                                     order=0,
                                                     message_type=LightClientProtocolMessageType.SettlementRequired,
                                                     wal=raiden.wal)

    @staticmethod
    def process_data_and_get_settlement_parameters(raiden: "RaidenService",
                                                   our_address: Address,
                                                   token_network_identifier: TokenNetworkID,
                                                   channel_identifier: ChannelID,
                                                   triggered_by_block_hash: BlockHash) -> SettlementParameters:

        log.debug("Processing settlement data")

        assert raiden.wal, "The Raiden Service must be initialized to handle events"
        canonical_identifier = CanonicalIdentifier(
            chain_identifier=raiden.chain.network_id,
            token_network_address=token_network_identifier,
            channel_identifier=channel_identifier,
        )
        payment_channel: PaymentChannel = raiden.chain.payment_channel(
            creator_address=our_address,
            canonical_identifier=canonical_identifier
        )
        token_network_proxy: TokenNetwork = payment_channel.token_network
        if not token_network_proxy.client.can_query_state_for_block(triggered_by_block_hash):
            # The only time this can happen is during restarts after a long time
            # when the triggered block ends up getting pruned
            # In that case it's safe to just use the latest view of the chain to
            # query the on-chain participant/channel details
            triggered_by_block_hash = token_network_proxy.client.blockhash_from_blocknumber(
                "latest"
            )
        participants_details = token_network_proxy.detail_participants(
            participant1=payment_channel.participant1,
            participant2=payment_channel.participant2,
            block_identifier=triggered_by_block_hash,
            channel_identifier=channel_identifier,
        )
        our_details = participants_details.our_details
        partner_details = participants_details.partner_details
        log_details = {
            "chain_id": canonical_identifier.chain_identifier,
            "token_network_identifier": canonical_identifier.token_network_address,
            "channel_identifier": canonical_identifier.channel_identifier,
            "node": pex(raiden.address),
            "partner": to_checksum_address(partner_details.address),
            "our_deposit": our_details.deposit,
            "our_withdrawn": our_details.withdrawn,
            "our_is_closer": our_details.is_closer,
            "our_balance_hash": to_hex(our_details.balance_hash),
            "our_nonce": our_details.nonce,
            "our_locksroot": to_hex(our_details.locksroot),
            "our_locked_amount": our_details.locked_amount,
            "partner_deposit": partner_details.deposit,
            "partner_withdrawn": partner_details.withdrawn,
            "partner_is_closer": partner_details.is_closer,
            "partner_balance_hash": to_hex(partner_details.balance_hash),
            "partner_nonce": partner_details.nonce,
            "partner_locksroot": to_hex(partner_details.locksroot),
            "partner_locked_amount": partner_details.locked_amount,
        }
        if our_details.balance_hash != EMPTY_HASH:
            event_record = get_event_with_balance_proof_by_balance_hash(
                storage=raiden.wal.storage,
                canonical_identifier=canonical_identifier,
                balance_hash=our_details.balance_hash,
            )
            if event_record.data is None:
                log.critical("our balance proof not found", **log_details)
                raise RaidenUnrecoverableError(
                    "Our balance proof could not be found in the database"
                )
            our_balance_proof = event_record.data.balance_proof
            our_transferred_amount = our_balance_proof.transferred_amount
            our_locked_amount = our_balance_proof.locked_amount
            our_locksroot = our_balance_proof.locksroot
        else:
            our_transferred_amount = 0
            our_locked_amount = 0
            our_locksroot = EMPTY_HASH
        if partner_details.balance_hash != EMPTY_HASH:
            state_change_record = get_state_change_with_balance_proof_by_balance_hash(
                storage=raiden.wal.storage,
                canonical_identifier=canonical_identifier,
                balance_hash=partner_details.balance_hash,
                sender=participants_details.partner_details.address,
            )
            if state_change_record.data is None:
                log.critical("partner balance proof not found", **log_details)
                raise RaidenUnrecoverableError(
                    "Partner balance proof could not be found in the database"
                )
            partner_balance_proof = state_change_record.data.balance_proof
            partner_transferred_amount = partner_balance_proof.transferred_amount
            partner_locked_amount = partner_balance_proof.locked_amount
            partner_locksroot = partner_balance_proof.locksroot
        else:
            partner_transferred_amount = 0
            partner_locked_amount = 0
            partner_locksroot = EMPTY_HASH

        return SettlementParameters(
            transferred_amount=our_transferred_amount,
            locked_amount=our_locked_amount,
            locksroot=our_locksroot,
            partner_transferred_amount=partner_transferred_amount,
            partner_locked_amount=partner_locked_amount,
            partner_locksroot=partner_locksroot,
            block_identifier=triggered_by_block_hash)
