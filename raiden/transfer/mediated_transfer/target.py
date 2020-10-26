import random

from datetime import date

from raiden.lightclient.handlers.light_client_message_handler import LightClientMessageHandler
from raiden.lightclient.handlers.light_client_service import LightClientService
from raiden.lightclient.models.light_client_payment import LightClientPayment, LightClientPaymentStatus
from raiden.lightclient.models.light_client_protocol_message import LightClientProtocolMessageType
from raiden.message_event_convertor import message_from_sendevent
from raiden.messages import SecretRequest
from raiden.transfer import channel, secret_registry
from raiden.transfer.architecture import Event, StateChange, TransitionResult
from raiden.transfer.events import EventPaymentReceivedSuccess, SendProcessed
from raiden.transfer.mediated_transfer.events import (
    CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
    EventUnlockClaimFailed,
    EventUnlockClaimSuccess,
    SendSecretRequest,
    SendSecretReveal,
    StoreMessageEvent, SendSecretRequestLight, SendSecretRevealLight)
from raiden.transfer.mediated_transfer.mediator import is_safe_to_wait
from raiden.transfer.mediated_transfer.state import TargetTransferState
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitTarget,
    ReceiveLockExpired,
    ReceiveSecretReveal,
    ActionInitTargetLight, ActionSendSecretRequestLight, ReceiveSecretRevealLight, ActionSendSecretRevealLight,
    ReceiveLockExpiredLight)
from raiden.transfer.state import NettingChannelState, message_identifier_from_prng
from raiden.transfer.state_change import Block, ContractReceiveSecretReveal, ReceiveUnlock, ReceiveUnlockLight
from raiden.transfer.utils import is_valid_secret_reveal
from raiden.utils.typing import (
    MYPY_ANNOTATION,
    Address,
    BlockHash,
    BlockNumber,
    List,
    Optional,
    TokenAmount,
    TokenNetworkID,
)


def sanity_check(
    old_state: Optional[TargetTransferState],
    new_state: Optional[TargetTransferState],
    channel_state: NettingChannelState,
) -> None:
    was_running = old_state is not None
    is_running = new_state is not None
    is_cleared = was_running and not is_running

    if old_state and is_cleared:
        lock = channel.get_lock(
            end_state=channel_state.partner_state, secrethash=old_state.transfer.lock.secrethash
        )
        assert lock is None, "The lock must be cleared once the task exists"
    elif new_state and is_running:
        # old_state can be None if the task is starting
        lock = channel.get_lock(
            end_state=channel_state.partner_state, secrethash=new_state.transfer.lock.secrethash
        )
        assert lock is not None, "The lock must not be cleared while the task is running"


def events_for_onchain_secretreveal(
    target_state: TargetTransferState,
    channel_state: NettingChannelState,
    block_number: BlockNumber,
    block_hash: BlockHash
) -> List[Event]:
    """ Emits the event for revealing the secret on-chain if the transfer
    can not be settled off-chain.
    """
    transfer = target_state.transfer
    expiration = transfer.lock.expiration

    safe_to_wait, _ = is_safe_to_wait(expiration, channel_state.reveal_timeout, block_number)
    secret_known_offchain = channel.is_secret_known_offchain(
        channel_state.partner_state, transfer.lock.secrethash
    )
    has_onchain_reveal_started = target_state.state == TargetTransferState.ONCHAIN_SECRET_REVEAL

    if not safe_to_wait and secret_known_offchain and not has_onchain_reveal_started:
        target_state.state = TargetTransferState.ONCHAIN_SECRET_REVEAL
        secret = channel.get_secret(channel_state.partner_state, transfer.lock.secrethash)
        assert secret, "secret should be known at this point"
        return secret_registry.events_for_onchain_secretreveal(
            channel_state=channel_state,
            secret=secret,
            expiration=expiration,
            block_hash=block_hash,
            target_state=target_state
        )

    return list()


def handle_inittarget(
    state_change: ActionInitTarget,
    channel_state: NettingChannelState,
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
    storage
) -> TransitionResult[TargetTransferState]:
    """ Handles an ActionInitTarget state change. """
    transfer = state_change.transfer
    route = state_change.route

    assert channel_state.identifier == transfer.balance_proof.channel_identifier
    is_valid, channel_events, errormsg, handle_invoice_result = channel.handle_receive_lockedtransfer(
        channel_state, transfer, storage
    )

    if is_valid:
        # A valid balance proof does not mean the payment itself is still valid.
        # e.g. the lock may be near expiration or have expired. This is fine. The
        # message with an unusable lock must be handled to properly synchronize the
        # local view of the partner's channel state, allowing the next balance
        # proofs to be handled. This however, must only be done once, which is
        # enforced by the nonce increasing sequentially, which is verified by
        # the handler handle_receive_lockedtransfer.
        target_state = TargetTransferState(route, transfer)

        safe_to_wait, _ = is_safe_to_wait(
            transfer.lock.expiration, channel_state.reveal_timeout, block_number
        )

        # If there is not enough time to safely unlock the lock on-chain
        # silently let the transfer expire. The target task must be created to
        # handle the ReceiveLockExpired state change, which will clear the
        # expired lock.
        #
        # We add a new validation.
        # It is verified that if there was an invoice it was paid successfully,
        # if it was not, the payment is interrupted
        # by not generating an event send secret request
        if safe_to_wait and handle_invoice_result['is_valid']:
            message_identifier = message_identifier_from_prng(pseudo_random_generator)
            recipient = transfer.initiator
            secret_request = SendSecretRequest(
                recipient=Address(recipient),
                channel_identifier=CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
                message_identifier=message_identifier,
                payment_identifier=transfer.payment_identifier,
                amount=transfer.lock.amount,
                expiration=transfer.lock.expiration,
                secrethash=transfer.lock.secrethash,
            )

            channel_events.append(secret_request)

        iteration = TransitionResult(target_state, channel_events)
    else:
        # If the balance proof is not valid, do *not* create a task. Otherwise it's
        # possible for an attacker to send multiple invalid transfers, and increase
        # the memory usage of this Node.
        assert errormsg, "handle_receive_lockedtransfer should return error msg if not valid"
        unlock_failed = EventUnlockClaimFailed(
            identifier=transfer.payment_identifier,
            secrethash=transfer.lock.secrethash,
            reason=errormsg,
        )
        channel_events.append(unlock_failed)
        iteration = TransitionResult(None, channel_events)

    return iteration


def handle_inittarget_light(
    state_change: ActionInitTargetLight,
    channel_state: NettingChannelState,
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
    storage
) -> TransitionResult[TargetTransferState]:
    """ Handles an ActionInitTarget state change. """
    transfer = state_change.transfer
    route = state_change.route

    assert channel_state.identifier == transfer.balance_proof.channel_identifier
    is_valid, channel_events, errormsg, handle_invoice_result = channel.handle_receive_lockedtransfer_light(
        channel_state, transfer, storage
    )

    if is_valid:
        # A valid balance proof does not mean the payment itself is still valid.
        # e.g. the lock may be near expiration or have expired. This is fine. The
        # message with an unusable lock must be handled to properly synchronize the
        # local view of the partner's channel state, allowing the next balance
        # proofs to be handled. This however, must only be done once, which is
        # enforced by the nonce increasing sequentially, which is verified by
        # the handler handle_receive_lockedtransfer.
        target_state = TargetTransferState(route, transfer)

        safe_to_wait, _ = is_safe_to_wait(
            transfer.lock.expiration, channel_state.reveal_timeout, block_number
        )

        # If there is not enough time to safely unlock the lock on-chain
        # silently let the transfer expire. The target task must be created to
        # handle the ReceiveLockExpired state change, which will clear the
        # expired lock.
        #
        # We add a new validation.
        # It is verified that if there was an invoice it was paid successfully,
        # if it was not, the payment is interrupted
        # by not generating an event send secret request
        if safe_to_wait and handle_invoice_result['is_valid']:
            payment = LightClientPayment(
                partner_address=state_change.transfer.initiator,
                is_lc_initiator=False,
                token_network_id=channel_state.token_network_identifier,
                amount=transfer.lock.amount,
                created_on=str(date.today()),
                payment_status=LightClientPaymentStatus.Pending,
                identifier=transfer.payment_identifier,
                light_client_address=transfer.target
            )

            payment_exists = LightClientService.get_light_client_payment(payment.payment_id, storage)
            if not payment_exists:
                LightClientMessageHandler.store_light_client_payment(payment, storage)

            message_identifier = message_identifier_from_prng(pseudo_random_generator)
            recipient = transfer.initiator
            secret_request = SendSecretRequest(
                recipient=Address(recipient),
                channel_identifier=CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
                message_identifier=message_identifier,
                payment_identifier=transfer.payment_identifier,
                amount=transfer.lock.amount,
                expiration=transfer.lock.expiration,
                secrethash=transfer.lock.secrethash,
            )

            store_locked_transfer_event = StoreMessageEvent(message_id=transfer.message_identifier,
                                                            payment_id=transfer.payment_identifier,
                                                            message_order=1,
                                                            message=state_change.signed_lockedtransfer,
                                                            is_signed=True,
                                                            message_type=LightClientProtocolMessageType.PaymentSuccessful,
                                                            light_client_address=transfer.target)

            secret_request_message = SecretRequest.from_event(secret_request)
            store_secret_request_event = StoreMessageEvent(message_id=message_identifier,
                                                           payment_id=transfer.payment_identifier,
                                                           message_order=5,
                                                           message=secret_request_message,
                                                           is_signed=False,
                                                           message_type=LightClientProtocolMessageType.PaymentSuccessful,
                                                           light_client_address=transfer.target)
            channel_events.append(store_secret_request_event)
            channel_events.append(store_locked_transfer_event)
        elif not safe_to_wait:
            # If transfer expired, persist the LockedTransfer in order that the LC can get it and respond with Delivered msg
            # Also persist the payment on with expired status
            payment = LightClientPayment(
                partner_address=state_change.transfer.initiator,
                is_lc_initiator=False,
                token_network_id=channel_state.token_network_identifier,
                amount=transfer.lock.amount,
                created_on=str(date.today()),
                payment_status=LightClientPaymentStatus.Expired,
                identifier=transfer.payment_identifier,
                light_client_address=transfer.target
            )
            LightClientMessageHandler.store_light_client_payment(payment, storage)
            store_expired_locked_transfer_event = StoreMessageEvent(
                message_id=transfer.message_identifier,
                payment_id=transfer.payment_identifier,
                message_order=1,
                message=state_change.signed_lockedtransfer,
                is_signed=True,
                message_type=LightClientProtocolMessageType.PaymentExpired,
                light_client_address=transfer.target
            )
            channel_events.append(store_expired_locked_transfer_event)
        iteration = TransitionResult(target_state, channel_events)
    else:
        # If the balance proof is not valid, do *not* create a task. Otherwise it's
        # possible for an attacker to send multiple invalid transfers, and increase
        # the memory usage of this Node.
        assert errormsg, "handle_receive_lockedtransfer should return error msg if not valid"
        unlock_failed = EventUnlockClaimFailed(
            identifier=transfer.payment_identifier,
            secrethash=transfer.lock.secrethash,
            reason=errormsg,
        )
        channel_events.append(unlock_failed)
        iteration = TransitionResult(None, channel_events)

    return iteration


def handle_send_secret_reveal_light(
    target_state: TargetTransferState,
    state_change: ActionSendSecretRevealLight,
) -> TransitionResult[TargetTransferState]:
    message_identifier = state_change.reveal_secret.message_identifier
    transfer = target_state.transfer
    # The recipient is the initiator of the payment cause the light client is the target of the payment
    recipient = state_change.receiver
    revealsecret = SendSecretRevealLight(
        sender=Address(state_change.sender),
        recipient=Address(recipient),
        channel_identifier=CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
        message_identifier=message_identifier,
        secret=state_change.reveal_secret.secret,
        signed_secret_reveal=state_change.reveal_secret
    )
    store_reveal_secret_event = StoreMessageEvent(message_id=message_identifier,
                                                  payment_id=transfer.payment_identifier,
                                                  message_order=9,
                                                  message=state_change.reveal_secret,
                                                  is_signed=True,
                                                  message_type=LightClientProtocolMessageType.PaymentSuccessful,
                                                  light_client_address=transfer.target)
    iteration = TransitionResult(target_state, [revealsecret, store_reveal_secret_event])
    return iteration


def handle_send_secret_request_light(
    target_state: TargetTransferState,
    state_change: ActionSendSecretRequestLight,
    channel_state: NettingChannelState,
    block_number: BlockNumber
) -> TransitionResult[TargetTransferState]:
    """ Handles an ActionInitTarget state change. """
    transfer = target_state.transfer

    assert channel_state.identifier == transfer.balance_proof.channel_identifier

    events = list()

    safe_to_wait, _ = is_safe_to_wait(
        transfer.lock.expiration, channel_state.reveal_timeout, block_number
    )

    # If there is not enough time to safely unlock the lock on-chain
    # silently let the transfer expire. The target task must be created to
    # handle the ReceiveLockExpired state change, which will clear the
    # expired lock.
    #
    # We add a new validation.
    # It is verified that if there was an invoice it was paid successfully,
    # if it was not, the payment is interrupted
    # by not generating an event send secret request
    if safe_to_wait:
        secret_request_light = SendSecretRequestLight(
            sender=Address(target_state.transfer.target),
            recipient=Address(target_state.transfer.initiator),
            channel_identifier=CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
            message_identifier=state_change.secret_request.message_identifier,
            payment_identifier=transfer.payment_identifier,
            amount=transfer.lock.amount,
            expiration=transfer.lock.expiration,
            secrethash=transfer.lock.secrethash,
            signed_secret_request=state_change.secret_request
        )

        store_secret_request_event = StoreMessageEvent(message_id=state_change.secret_request.message_identifier,
                                                       payment_id=transfer.payment_identifier,
                                                       message_order=5,
                                                       message=state_change.secret_request,
                                                       is_signed=True,
                                                       message_type=LightClientProtocolMessageType.PaymentSuccessful,
                                                       light_client_address=transfer.target)
        events.append(secret_request_light)
        events.append(store_secret_request_event)

    iteration = TransitionResult(target_state, events)
    return iteration


def handle_offchain_secretreveal(
    target_state: TargetTransferState,
    state_change: ReceiveSecretReveal,
    channel_state: NettingChannelState,
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
) -> TransitionResult[TargetTransferState]:
    """ Validates and handles a ReceiveSecretReveal state change. """
    valid_secret = is_valid_secret_reveal(
        state_change=state_change,
        transfer_secrethash=target_state.transfer.lock.secrethash,
        secret=state_change.secret,
    )
    has_transfer_expired = channel.is_transfer_expired(
        transfer=target_state.transfer, affected_channel=channel_state, block_number=block_number
    )

    if valid_secret and not has_transfer_expired:
        channel.register_offchain_secret(
            channel_state=channel_state,
            secret=state_change.secret,
            secrethash=state_change.secrethash,
        )

        route = target_state.route
        message_identifier = message_identifier_from_prng(pseudo_random_generator)
        target_state.state = TargetTransferState.OFFCHAIN_SECRET_REVEAL
        target_state.secret = state_change.secret
        recipient = route.node_address

        reveal = SendSecretReveal(
            recipient=recipient,
            channel_identifier=CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
            message_identifier=message_identifier,
            secret=target_state.secret,
        )

        iteration = TransitionResult(target_state, [reveal])

    else:
        # TODO: event for byzantine behavior
        iteration = TransitionResult(target_state, list())

    return iteration


def handle_offchain_secretreveal_light(
    target_state: TargetTransferState,
    state_change: ReceiveSecretRevealLight,
    channel_state: NettingChannelState,
    block_number: BlockNumber,
) -> TransitionResult[TargetTransferState]:
    """ Validates and handles a ReceiveSecretReveal state change. """
    valid_secret = is_valid_secret_reveal(
        state_change=state_change,
        transfer_secrethash=target_state.transfer.lock.secrethash,
        secret=state_change.secret,
    )
    has_transfer_expired = channel.is_transfer_expired(
        transfer=target_state.transfer, affected_channel=channel_state, block_number=block_number
    )

    if valid_secret and not has_transfer_expired:
        # TODO the secret should be encrypted with LC's public key
        channel.register_offchain_secret(
            channel_state=channel_state,
            secret=state_change.secret,
            secrethash=state_change.secrethash,
        )

        target_state.state = TargetTransferState.OFFCHAIN_SECRET_REVEAL
        target_state.secret = state_change.secret

        # Store reveal secret 7, create reveal secret 9 and store it for LC signing.

        received_reveal_secret = state_change.secret_reveal_message

        store_received_reveal = StoreMessageEvent(
            message_id=received_reveal_secret.message_identifier,
            payment_id=target_state.transfer.payment_identifier,
            message_order=7,
            message=received_reveal_secret,
            is_signed=True,
            message_type=LightClientProtocolMessageType.PaymentSuccessful,
            light_client_address=target_state.transfer.target
        )

        iteration = TransitionResult(target_state, [store_received_reveal])

    else:
        # TODO: event for byzantine behavior
        iteration = TransitionResult(target_state, list())

    return iteration


def handle_onchain_secretreveal(
    target_state: TargetTransferState,
    state_change: ContractReceiveSecretReveal,
    channel_state: NettingChannelState,
) -> TransitionResult[TargetTransferState]:
    """ Validates and handles a ContractReceiveSecretReveal state change. """
    valid_secret = is_valid_secret_reveal(
        state_change=state_change,
        transfer_secrethash=target_state.transfer.lock.secrethash,
        secret=state_change.secret,
    )

    if valid_secret:
        channel.register_onchain_secret(
            channel_state=channel_state,
            secret=state_change.secret,
            secrethash=state_change.secrethash,
            secret_reveal_block_number=state_change.block_number,
        )

        target_state.state = TargetTransferState.ONCHAIN_UNLOCK
        target_state.secret = state_change.secret

    return TransitionResult(target_state, list())


def handle_unlock_light(
    target_state: TargetTransferState,
    state_change: ReceiveUnlockLight,
    channel_state: NettingChannelState,
) -> TransitionResult[TargetTransferState]:
    """ Handles a ReceiveUnlockLight state change. """

    is_valid, events, _ = channel.handle_unlock_light(channel_state, state_change)
    next_target_state: Optional[TargetTransferState] = target_state

    if is_valid:
        transfer = target_state.transfer
        payment_received_success = EventPaymentReceivedSuccess(
            payment_network_identifier=channel_state.payment_network_identifier,
            token_network_identifier=TokenNetworkID(channel_state.token_network_identifier),
            identifier=transfer.payment_identifier,
            amount=TokenAmount(transfer.lock.amount),
            initiator=transfer.initiator,
        )

        unlock_success = EventUnlockClaimSuccess(
            transfer.payment_identifier, transfer.lock.secrethash
        )

        store_unlock_message = StoreMessageEvent(
            message_id=state_change.signed_unlock.message_identifier,
            payment_id=state_change.signed_unlock.payment_identifier,
            message_order=11,
            message=state_change.signed_unlock,
            is_signed=True,
            message_type=LightClientProtocolMessageType.PaymentSuccessful,
            light_client_address=transfer.target
        )

        events.extend([payment_received_success, unlock_success, store_unlock_message])
        next_target_state = None

    return TransitionResult(next_target_state, events)


def handle_unlock(
    target_state: TargetTransferState,
    state_change: ReceiveUnlock,
    channel_state: NettingChannelState,
) -> TransitionResult[TargetTransferState]:
    """ Handles a ReceiveUnlock state change. """
    balance_proof_sender = state_change.balance_proof.sender

    is_valid, events, _ = channel.handle_unlock(channel_state, state_change)
    next_target_state: Optional[TargetTransferState] = target_state

    if is_valid:
        transfer = target_state.transfer
        payment_received_success = EventPaymentReceivedSuccess(
            payment_network_identifier=channel_state.payment_network_identifier,
            token_network_identifier=TokenNetworkID(channel_state.token_network_identifier),
            identifier=transfer.payment_identifier,
            amount=TokenAmount(transfer.lock.amount),
            initiator=transfer.initiator,
        )

        unlock_success = EventUnlockClaimSuccess(
            transfer.payment_identifier, transfer.lock.secrethash
        )

        send_processed = SendProcessed(
            recipient=balance_proof_sender,
            channel_identifier=CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
            message_identifier=state_change.message_identifier,
        )

        events.extend([payment_received_success, unlock_success, send_processed])
        next_target_state = None

    return TransitionResult(next_target_state, events)


def handle_block(
    target_state: TargetTransferState,
    channel_state: NettingChannelState,
    block_number: BlockNumber,
    block_hash: BlockHash
) -> TransitionResult[TargetTransferState]:
    """ After Raiden learns about a new block this function must be called to
    handle expiration of the hash time lock.
    """
    transfer = target_state.transfer
    events: List[Event] = list()
    lock = transfer.lock

    secret_known = channel.is_secret_known(channel_state.partner_state, lock.secrethash)
    lock_has_expired, _ = channel.is_lock_expired(
        end_state=channel_state.our_state,
        lock=lock,
        block_number=block_number,
        lock_expiration_threshold=channel.get_receiver_expiration_threshold(lock),
    )

    if lock_has_expired and target_state.state != "expired":
        failed = EventUnlockClaimFailed(
            identifier=transfer.payment_identifier,
            secrethash=transfer.lock.secrethash,
            reason=f"lock expired",
        )
        target_state.state = TargetTransferState.EXPIRED
        events = [failed]
    elif secret_known:
        events = events_for_onchain_secretreveal(
            target_state=target_state,
            channel_state=channel_state,
            block_number=block_number,
            block_hash=block_hash,
        )

    return TransitionResult(target_state, events)


def handle_lock_expired(
    target_state: TargetTransferState,
    state_change: ReceiveLockExpired,
    channel_state: NettingChannelState,
    block_number: BlockNumber,
) -> TransitionResult[TargetTransferState]:
    """Remove expired locks from channel states."""
    result = channel.handle_receive_lock_expired(
        channel_state=channel_state, state_change=state_change, block_number=block_number
    )
    assert result.new_state, "handle_receive_lock_expired should not delete the task"

    if not channel.get_lock(result.new_state.partner_state, target_state.transfer.lock.secrethash):
        transfer = target_state.transfer
        unlock_failed = EventUnlockClaimFailed(
            identifier=transfer.payment_identifier,
            secrethash=transfer.lock.secrethash,
            reason="Lock expired",
        )
        result.events.append(unlock_failed)
        return TransitionResult(None, result.events)

    return TransitionResult(target_state, result.events)


def handle_lock_expired_light(
    target_state: TargetTransferState,
    state_change: ReceiveLockExpiredLight,
    channel_state: NettingChannelState,
    block_number: BlockNumber,
    storage
) -> TransitionResult[TargetTransferState]:
    """Update the status of the payment to Expired ."""
    LightClientMessageHandler.update_light_client_payment_status(target_state.transfer.payment_identifier,
                                                                 LightClientPaymentStatus.Expired, storage)
    """Remove expired locks from channel states."""
    result = channel.handle_receive_lock_expired_light(
        channel_state=channel_state, state_change=state_change, block_number=block_number,
        payment_id=target_state.transfer.payment_identifier
    )
    assert result.new_state, "handle_receive_lock_expired_light should not delete the task"

    if not channel.get_lock(result.new_state.partner_state, target_state.transfer.lock.secrethash):
        transfer = target_state.transfer
        unlock_failed = EventUnlockClaimFailed(
            identifier=transfer.payment_identifier,
            secrethash=transfer.lock.secrethash,
            reason="Lock expired",
        )
        result.events.append(unlock_failed)
        return TransitionResult(None, result.events)

    return TransitionResult(target_state, result.events)


def state_transition(
    target_state: Optional[TargetTransferState],
    state_change: StateChange,
    channel_state: NettingChannelState,
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
    storage
) -> TransitionResult[TargetTransferState]:
    """ State machine for the target node of a mediated transfer. """
    # pylint: disable=too-many-branches,unidiomatic-typecheck

    iteration = TransitionResult(target_state, list())
    if type(state_change) == ActionInitTarget:
        assert isinstance(state_change, ActionInitTarget), MYPY_ANNOTATION
        if target_state is None:
            iteration = handle_inittarget(
                state_change, channel_state, pseudo_random_generator, block_number, storage
            )
    elif type(state_change) == ActionInitTargetLight:
        assert isinstance(state_change, ActionInitTargetLight), MYPY_ANNOTATION
        if target_state is None:
            iteration = handle_inittarget_light(
                state_change, channel_state, pseudo_random_generator, block_number, storage
            )
    elif type(state_change) == ActionSendSecretRequestLight:
        assert isinstance(state_change, ActionSendSecretRequestLight), MYPY_ANNOTATION
        assert target_state, "ActionSendSecretRequestLight should be accompanied by a valid target state"
        iteration = handle_send_secret_request_light(
            target_state, state_change, channel_state, block_number
        )
    elif type(state_change) == ActionSendSecretRevealLight:
        assert isinstance(state_change, ActionSendSecretRevealLight), MYPY_ANNOTATION
        assert target_state, "ActionSendSecretRevealLight should be accompanied by a valid target state"
        iteration = handle_send_secret_reveal_light(
            target_state, state_change
        )
    elif type(state_change) == Block:
        assert isinstance(state_change, Block), MYPY_ANNOTATION
        assert state_change.block_number == block_number
        assert target_state, "Block state changes should be accompanied by a valid target state"

        iteration = handle_block(
            target_state=target_state,
            channel_state=channel_state,
            block_number=state_change.block_number,
            block_hash=state_change.block_hash
        )
    elif type(state_change) == ReceiveSecretReveal:
        assert isinstance(state_change, ReceiveSecretReveal), MYPY_ANNOTATION
        assert target_state, "ReceiveSecretReveal should be accompanied by a valid target state"
        iteration = handle_offchain_secretreveal(
            target_state=target_state,
            state_change=state_change,
            channel_state=channel_state,
            pseudo_random_generator=pseudo_random_generator,
            block_number=block_number,
        )
    elif type(state_change) == ReceiveSecretRevealLight:
        assert isinstance(state_change, ReceiveSecretRevealLight), MYPY_ANNOTATION
        iteration = handle_offchain_secretreveal_light(
            target_state=target_state,
            state_change=state_change,
            channel_state=channel_state,
            block_number=block_number
        )
    elif type(state_change) == ContractReceiveSecretReveal:
        assert isinstance(state_change, ContractReceiveSecretReveal), MYPY_ANNOTATION
        msg = "ContractReceiveSecretReveal should be accompanied by a valid target state"
        assert target_state, msg
        iteration = handle_onchain_secretreveal(target_state, state_change, channel_state)
    elif type(state_change) == ReceiveUnlock:
        assert isinstance(state_change, ReceiveUnlock), MYPY_ANNOTATION
        assert target_state, "ReceiveUnlock should be accompanied by a valid target state"
        iteration = handle_unlock(
            target_state=target_state, state_change=state_change, channel_state=channel_state
        )
    elif type(state_change) == ReceiveUnlockLight:
        assert isinstance(state_change, ReceiveUnlockLight), MYPY_ANNOTATION
        assert target_state, "ReceiveUnlock should be accompanied by a valid target state"
        iteration = handle_unlock_light(
            target_state=target_state, state_change=state_change, channel_state=channel_state
        )
    elif type(state_change) == ReceiveLockExpired:
        assert isinstance(state_change, ReceiveLockExpired), MYPY_ANNOTATION
        assert target_state, "ReceiveLockExpired should be accompanied by a valid target state"
        iteration = handle_lock_expired(
            target_state=target_state,
            state_change=state_change,
            channel_state=channel_state,
            block_number=block_number,
        )
    elif type(state_change) == ReceiveLockExpiredLight:
        assert isinstance(state_change, ReceiveLockExpiredLight), MYPY_ANNOTATION
        assert target_state, "ReceiveLockExpired should be accompanied by a valid target state"
        iteration = handle_lock_expired_light(
            target_state=target_state,
            state_change=state_change,
            channel_state=channel_state,
            block_number=block_number,
            storage=storage
        )

    sanity_check(
        old_state=target_state, new_state=iteration.new_state, channel_state=channel_state
    )

    return iteration
