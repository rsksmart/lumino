import structlog

from eth_utils import to_checksum_address

from raiden.constants import EMPTY_SECRET
from raiden.lightclient.handlers.light_client_message_handler import LightClientMessageHandler
from raiden.lightclient.handlers.light_client_service import LightClientService
from raiden.messages import (
    Delivered,
    LockedTransfer,
    LockExpired,
    Message,
    Processed,
    RefundTransfer,
    RevealSecret,
    SecretRequest,
    Unlock,
)
from raiden.raiden_service import RaidenService
from raiden.transfer import views
from raiden.transfer.architecture import StateChange
from raiden.transfer.mediated_transfer.state import lockedtransfersigned_from_message
from raiden.transfer.mediated_transfer.state_change import (
    ReceiveLockExpired,
    ReceiveSecretRequest,
    ReceiveSecretReveal,
    ReceiveTransferRefund,
    ActionTransferReroute,
    ReceiveSecretRequestLight, ReceiveSecretRevealLight, ReceiveTransferCancelRoute, ReceiveLockExpiredLight,
    StoreRefundTransferLight, ActionTransferRerouteLight)
from raiden.transfer.state import balanceproof_from_envelope
from raiden.transfer.state_change import ReceiveDelivered, ReceiveProcessed, ReceiveUnlock, ReceiveUnlockLight
from raiden.utils import pex, random_secret
from raiden.utils.typing import MYPY_ANNOTATION

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


class MessageHandler:
    def on_message(self, raiden: RaidenService, message: Message, is_light_client: bool = False) -> None:
        # pylint: disable=unidiomatic-typecheck
        print("On received message " + str(type(message)))

        if type(message) == SecretRequest:
            assert isinstance(message, SecretRequest), MYPY_ANNOTATION
            self.handle_message_secretrequest(raiden, message, is_light_client)

        elif type(message) == RevealSecret:
            assert isinstance(message, RevealSecret), MYPY_ANNOTATION
            self.handle_message_revealsecret(raiden, message, is_light_client)

        elif type(message) == Unlock:
            assert isinstance(message, Unlock), MYPY_ANNOTATION
            self.handle_message_unlock(raiden, message, is_light_client)

        elif type(message) == LockExpired:
            assert isinstance(message, LockExpired), MYPY_ANNOTATION
            self.handle_message_lockexpired(raiden, message, is_light_client)

        elif type(message) == RefundTransfer:
            assert isinstance(message, RefundTransfer), MYPY_ANNOTATION
            self.handle_message_refundtransfer(raiden, message, is_light_client)

        elif type(message) == LockedTransfer:
            assert isinstance(message, LockedTransfer), MYPY_ANNOTATION
            self.handle_message_lockedtransfer(raiden, message)

        elif type(message) == Delivered:
            assert isinstance(message, Delivered), MYPY_ANNOTATION
            self.handle_message_delivered(raiden, message, is_light_client)

        elif type(message) == Processed:
            assert isinstance(message, Processed), MYPY_ANNOTATION
            self.handle_message_processed(raiden, message, is_light_client)
        else:
            log.error("Unknown message cmdid {}".format(message.cmdid))

    @staticmethod
    def handle_message_secretrequest(raiden: RaidenService, message: SecretRequest,
                                     is_light_client: bool = False) -> None:

        if is_light_client:
            secret_request_light = ReceiveSecretRequestLight(
                message.payment_identifier,
                message.amount,
                message.expiration,
                message.secrethash,
                message.sender,
                message
            )
            raiden.handle_and_track_state_change(secret_request_light)
        else:
            secret_request = ReceiveSecretRequest(
                message.payment_identifier,
                message.amount,
                message.expiration,
                message.secrethash,
                message.sender,
            )
            raiden.handle_and_track_state_change(secret_request)

    @staticmethod
    def handle_message_revealsecret(raiden: RaidenService, message: RevealSecret, is_light_client=False) -> None:
        if is_light_client:
            state_change = ReceiveSecretRevealLight(message.secret, message.sender, message)
            raiden.handle_and_track_state_change(state_change)
        else:
            state_change = ReceiveSecretReveal(message.secret, message.sender)
            raiden.handle_and_track_state_change(state_change)

    @staticmethod
    def handle_message_unlock(raiden: RaidenService, message: Unlock, is_light_client=False) -> None:
        balance_proof = balanceproof_from_envelope(message)
        if is_light_client:
            state_change = ReceiveUnlockLight(
                message_identifier=message.message_identifier,
                secret=message.secret,
                balance_proof=balance_proof,
                signed_unlock=message
            )
            raiden.handle_and_track_state_change(state_change)
        else:
            state_change = ReceiveUnlock(
                message_identifier=message.message_identifier,
                secret=message.secret,
                balance_proof=balance_proof,
            )
            raiden.handle_and_track_state_change(state_change)

    @staticmethod
    def handle_message_lockexpired(raiden: RaidenService, message: LockExpired, is_light_client=False) -> None:
        balance_proof = balanceproof_from_envelope(message)
        if is_light_client:
            state_change = ReceiveLockExpiredLight(
                balance_proof=balance_proof,
                secrethash=message.secrethash,
                message_identifier=message.message_identifier,
                lock_expired=message
            )
            raiden.handle_and_track_state_change(state_change)
        else:
            state_change = ReceiveLockExpired(
                balance_proof=balance_proof,
                secrethash=message.secrethash,
                message_identifier=message.message_identifier,
            )
            raiden.handle_and_track_state_change(state_change)

    @staticmethod
    def handle_message_refundtransfer(raiden: RaidenService, message: RefundTransfer, is_light_client=False) -> None:
        chain_state = views.state_from_raiden(raiden)
        from_transfer = lockedtransfersigned_from_message(message)

        role = views.get_transfer_role(
            chain_state=chain_state, secrethash=from_transfer.lock.secrethash
        )
        state_change: StateChange
        if role == "initiator":

            state_change = ReceiveTransferCancelRoute(
                balance_proof=from_transfer.balance_proof,
                transfer=from_transfer,
                sender=from_transfer.balance_proof.sender,  # pylint: disable=no-member
            )
            raiden.handle_and_track_state_change(state_change)

            # Currently, the only case where we can be initiators and not
            # know the secret is if the transfer is part of an atomic swap. In
            # the case of an atomic swap, we will not try to re-route the
            # transfer. In all other cases we can try to find another route
            # (and generate a new secret)
            old_secret = views.get_transfer_secret(chain_state, from_transfer.lock.secrethash)
            is_secret_known = old_secret is not None and old_secret != EMPTY_SECRET

            if is_light_client:
                if is_secret_known:
                    state_change = ActionTransferRerouteLight(
                        transfer=from_transfer,
                        secret=random_secret(),
                        refund_transfer=message
                    )
                    print("raiden/message_handler.py:184 >>>> Triggering ActionTransferRerouteLight")
                    raiden.handle_and_track_state_change(state_change)
            else:
                if is_secret_known:
                    state_change = ActionTransferReroute(
                        transfer=from_transfer,
                        secret=random_secret()
                    )
                    raiden.handle_and_track_state_change(state_change)

        else:
            # TODO marcosmartinez7 handle when a light client is a mediator or target.
            state_change = ReceiveTransferRefund(transfer=from_transfer)
            raiden.handle_and_track_state_change(state_change)



    @staticmethod
    def handle_message_lockedtransfer(raiden: RaidenService, message: LockedTransfer) -> None:
        secrethash = message.lock.secrethash
        # We must check if the secret was registered against the latest block,
        # even if the block is forked away and the transaction that registers
        # the secret is removed from the blockchain. The rationale here is that
        # someone else does know the secret, regardless of the chain state, so
        # the node must not use it to start a payment.
        #
        # For this particular case, it's preferable to use `latest` instead of
        # having a specific block_hash, because it's preferable to know if the secret`
        # was ever known, rather than having a consistent view of the blockchain.
        registered = raiden.default_secret_registry.is_secret_registered(
            secrethash=secrethash, block_identifier="latest"
        )
        if registered:
            log.warning(
                f"Ignoring received locked transfer with secrethash {pex(secrethash)} "
                f"since it is already registered in the secret registry"
            )
            return

        # TODO marcosmartinez7: unimplemented mediated transfer for light clients
        is_handled_light_client = LightClientService.is_handled_lc(to_checksum_address(message.recipient),
                                                                   raiden.wal)

        if message.target == raiden.address:
            raiden.target_mediated_transfer(message)
        elif is_handled_light_client:
            raiden.target_mediated_transfer_light(message)
        else:
            raiden.mediate_mediated_transfer(message)

    @classmethod
    def handle_message_processed(cls, raiden: RaidenService, message: Processed, is_light_client: bool = False) -> None:
        processed = ReceiveProcessed(message.sender, message.message_identifier)
        raiden.handle_and_track_state_change(processed)
        if is_light_client:
            LightClientMessageHandler.store_lc_processed(message, raiden.wal)

    @classmethod
    def handle_message_delivered(cls, raiden: RaidenService, message: Delivered, is_light_client: bool = False) -> None:
        delivered = ReceiveDelivered(message.sender, message.delivered_message_identifier)
        raiden.handle_and_track_state_change(delivered)
        if is_light_client:
            LightClientMessageHandler.store_lc_delivered(message, raiden.wal)
