import random

from eth_utils import keccak

from raiden.lightclient.models.light_client_protocol_message import LightClientProtocolMessageType

from raiden.messages import RefundTransfer

from raiden.transfer import channel, routes
from raiden.transfer.architecture import Event, StateChange, TransitionResult
from raiden.transfer.events import EventPaymentSentFailed
from raiden.transfer.mediated_transfer import initiator
from raiden.transfer.mediated_transfer.events import (
    EventUnlockClaimFailed,
    EventUnlockFailed,
    StoreMessageEvent
)
from raiden.transfer.mediated_transfer.state import (
    InitiatorPaymentState,
    InitiatorTransferState,
    TransferDescriptionWithSecretState,
)
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitInitiator,
    ReceiveLockExpired,
    ReceiveSecretRequest,
    ReceiveSecretReveal,
    ActionTransferReroute,
    ActionInitInitiatorLight, ReceiveSecretRequestLight, ActionSendSecretRevealLight, ReceiveSecretRevealLight,
    ReceiveTransferCancelRoute, StoreRefundTransferLight)
from raiden.transfer.state import RouteState
from raiden.transfer.state_change import ActionCancelPayment, Block, ContractReceiveSecretReveal
from raiden.utils.typing import (
    MYPY_ANNOTATION,
    BlockNumber,
    ChannelMap,
    List,
    Optional,
    SecretHash,
    TokenNetworkID,
    cast,
)


def clear_if_finalized(iteration: TransitionResult, ) -> TransitionResult[InitiatorPaymentState]:
    """ Clear the initiator payment task if all transfers have been finalized
    or expired. """
    state = cast(InitiatorPaymentState, iteration.new_state)

    if state is None:
        return iteration

    if len(state.initiator_transfers) == 0:
        return TransitionResult(None, iteration.events)

    return iteration


def transfer_exists(payment_state: InitiatorPaymentState, secrethash: SecretHash) -> bool:
    return secrethash in payment_state.initiator_transfers


def cancel_other_transfers(payment_state: InitiatorPaymentState) -> None:
    for initiator_state in payment_state.initiator_transfers.values():
        initiator_state.transfer_state = "transfer_cancelled"


def can_cancel(initiator: InitiatorTransferState) -> bool:
    """ A transfer is only cancellable until the secret is revealed. """
    return initiator is None or initiator.revealsecret is None


def events_for_cancel_current_route(
    transfer_description: TransferDescriptionWithSecretState,
) -> List[Event]:
    unlock_failed = EventUnlockFailed(
        identifier=transfer_description.payment_identifier,
        secrethash=transfer_description.secrethash,
        reason="route was canceled",
    )
    return [unlock_failed]


def cancel_current_route(
    payment_state: InitiatorPaymentState, initiator_state: InitiatorTransferState
) -> List[Event]:
    """ Cancel current route.

    This allows a new route to be tried.
    """
    assert can_cancel(initiator_state), "Cannot cancel a route after the secret is revealed"

    transfer_description = initiator_state.transfer_description

    payment_state.cancelled_channels.append(initiator_state.channel_identifier)

    return events_for_cancel_current_route(transfer_description)


def maybe_try_new_route(
    payment_state: InitiatorPaymentState,
    initiator_state: InitiatorTransferState,
    transfer_description: TransferDescriptionWithSecretState,
    available_routes: List[RouteState],
    channelidentifiers_to_channels: ChannelMap,
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
) -> TransitionResult[InitiatorPaymentState]:
    events: List[Event] = list()
    if can_cancel(initiator_state):
        cancel_events = cancel_current_route(payment_state, initiator_state)

        sub_iteration = initiator.try_new_route(
            channelidentifiers_to_channels=channelidentifiers_to_channels,
            available_routes=available_routes,
            transfer_description=transfer_description,
            pseudo_random_generator=pseudo_random_generator,
            block_number=block_number,
        )

        events.extend(cancel_events)
        events.extend(sub_iteration.events)

        if sub_iteration.new_state is None:
            # Here we don't delete the initiator state, but instead let it live.
            # It will be deleted when the lock expires. We do that so that we
            # still have an initiator payment task around to process the
            # LockExpired message that our partner will send us.
            # https://github.com/raiden-network/raiden/issues/3146#issuecomment-447378046
            return TransitionResult(payment_state, events)

        new_transfer = sub_iteration.new_state.transfer
        payment_state.initiator_transfers[new_transfer.lock.secrethash] = sub_iteration.new_state

    return TransitionResult(payment_state, events)


def subdispatch_to_initiatortransfer(
    payment_state: InitiatorPaymentState,
    initiator_state: InitiatorTransferState,
    state_change: StateChange,
    channelidentifiers_to_channels: ChannelMap,
    pseudo_random_generator: random.Random,
) -> TransitionResult[InitiatorTransferState]:
    print("initiator_manager subdispatch_to_initiatortransfer")

    channel_identifier = initiator_state.channel_identifier
    channel_state = channelidentifiers_to_channels[initiator_state.transfer_description.initiator].get(
        channel_identifier)
    if not channel_state:
        return TransitionResult(initiator_state, list())

    sub_iteration = initiator.state_transition(
        initiator_state=initiator_state,
        state_change=state_change,
        channel_state=channel_state,
        pseudo_random_generator=pseudo_random_generator,
    )

    if sub_iteration.new_state is None:
        print("No new state, payment task for initiator ends")
        del payment_state.initiator_transfers[initiator_state.transfer.lock.secrethash]

    return sub_iteration


def subdispatch_to_all_initiatortransfer(
    payment_state: InitiatorPaymentState,
    state_change: StateChange,
    channelidentifiers_to_channels: ChannelMap,
    pseudo_random_generator: random.Random,
) -> TransitionResult[InitiatorPaymentState]:
    events = list()
    """ Copy and iterate over the list of keys because this loop
    will alter the `initiator_transfers` list and this is not
    allowed if iterating over the original list.
    """
    print("Block initiator manager subdispatch_to_all_initiatortransfer")
    for secrethash in list(payment_state.initiator_transfers.keys()):
        initiator_state = payment_state.initiator_transfers[secrethash]
        sub_iteration = subdispatch_to_initiatortransfer(
            payment_state=payment_state,
            initiator_state=initiator_state,
            state_change=state_change,
            channelidentifiers_to_channels=channelidentifiers_to_channels,
            pseudo_random_generator=pseudo_random_generator,
        )
        events.extend(sub_iteration.events)
    return TransitionResult(payment_state, events)


def handle_block(
    payment_state: InitiatorPaymentState,
    state_change: Block,
    channelidentifiers_to_channels: ChannelMap,
    pseudo_random_generator: random.Random,
) -> TransitionResult[InitiatorPaymentState]:
    return subdispatch_to_all_initiatortransfer(
        payment_state=payment_state,
        state_change=state_change,
        channelidentifiers_to_channels=channelidentifiers_to_channels,
        pseudo_random_generator=pseudo_random_generator,
    )


def handle_init(
    payment_state: Optional[InitiatorPaymentState],
    state_change: ActionInitInitiator,
    channelidentifiers_to_channels: ChannelMap,
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
) -> TransitionResult[InitiatorPaymentState]:
    sub_iteration = initiator.try_new_route(
        channelidentifiers_to_channels=channelidentifiers_to_channels,
        available_routes=state_change.routes,
        transfer_description=state_change.transfer,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    if sub_iteration.new_state:
        # TODO marcosmartinez7 here the routes are always all routes, because the ActionInitInitiator doesnt take into account cancelled routes.
        # Cancelled routes are added when a refund message comes.
        payment_state = InitiatorPaymentState(
            routes=state_change.routes,
            initiator_transfers={
                sub_iteration.new_state.transfer.lock.secrethash: sub_iteration.new_state
            }
        )

    return TransitionResult(payment_state,  sub_iteration.events)


def handle_init_light(
    payment_state: Optional[InitiatorPaymentState],
    state_change: ActionInitInitiatorLight,
    channelidentifiers_to_channels: ChannelMap,
) -> TransitionResult[InitiatorPaymentState]:
    events: List[Event] = list()
    sub_iteration = initiator.try_new_route_light(
        channelidentifiers_to_channels=channelidentifiers_to_channels,
        channel_state=state_change.current_channel,
        transfer_description=state_change.transfer,
        signed_locked_transfer=state_change.signed_locked_transfer
    )

    events = sub_iteration.events
    if sub_iteration.new_state:
        if not state_change.is_retry_route:
            # TODO marcosmartinez7 routes here can be handled better as they can be part of the state change.
            # For now the routes are all the possible routes - the routes that were marked as cancelled on payment refund
            payment_state = InitiatorPaymentState(
                routes=[],
                initiator_transfers={
                    sub_iteration.new_state.transfer.lock.secrethash: sub_iteration.new_state
                }
            )
        else:
            new_transfer = sub_iteration.new_state.transfer
            payment_state.initiator_transfers[new_transfer.lock.secrethash] = sub_iteration.new_state

    return TransitionResult(payment_state, events)


def handle_cancelpayment(
    payment_state: InitiatorPaymentState, channelidentifiers_to_channels: ChannelMap
) -> TransitionResult[InitiatorPaymentState]:
    """ Cancel the payment and all related transfers. """
    # Cannot cancel a transfer after the secret is revealed
    events = list()
    for initiator_state in payment_state.initiator_transfers.values():
        channel_identifier = initiator_state.channel_identifier
        channel_state = channelidentifiers_to_channels.get(channel_identifier)

        if not channel_state:
            continue

        if can_cancel(initiator_state):
            transfer_description = initiator_state.transfer_description
            cancel_events = cancel_current_route(payment_state, initiator_state)

            initiator_state.transfer_state = "transfer_cancelled"

            cancel = EventPaymentSentFailed(
                payment_network_identifier=channel_state.payment_network_identifier,
                token_network_identifier=TokenNetworkID(channel_state.token_network_identifier),
                identifier=transfer_description.payment_identifier,
                target=transfer_description.target,
                reason="user canceled payment",
            )
            cancel_events.append(cancel)

            events.extend(cancel_events)

    return TransitionResult(payment_state, events)


def handle_failroute(
    payment_state: InitiatorPaymentState, state_change: ReceiveTransferCancelRoute
) -> TransitionResult[InitiatorPaymentState]:

    events: List[Event] = list()
    initiator_state = payment_state.initiator_transfers.get(state_change.transfer.lock.secrethash)
    if initiator_state is not None and can_cancel(initiator_state):
        cancel_events = cancel_current_route(payment_state, initiator_state)
        events.extend(cancel_events)

    return TransitionResult(payment_state, events)


def handle_transferreroute(
    payment_state: InitiatorPaymentState,
    state_change: ActionTransferReroute,
    channelidentifiers_to_channels: ChannelMap,
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
    storage
) -> TransitionResult[InitiatorPaymentState]:
    try:
        initiator_state = payment_state.initiator_transfers.get(state_change.transfer.lock.secrethash)
        channel_identifier = initiator_state.channel_identifier
        channel_state = channelidentifiers_to_channels[initiator_state.transfer.initiator].get(channel_identifier)
    except KeyError:
        return TransitionResult(payment_state, list())

    refund_transfer = state_change.transfer
    original_transfer = initiator_state.transfer

    is_valid_lock = (
        refund_transfer.lock.secrethash == original_transfer.lock.secrethash
        and refund_transfer.lock.amount == original_transfer.lock.amount
        and refund_transfer.lock.expiration == original_transfer.lock.expiration
    )

    is_valid_refund = channel.refund_transfer_matches_transfer(refund_transfer, original_transfer)
    is_valid, channel_events, _, _ = channel.handle_receive_lockedtransfer(
        channel_state, refund_transfer, None
    )

    if not is_valid_lock or not is_valid_refund or not is_valid:
        return TransitionResult(payment_state, list())

    events: List[Event] = []
    events.extend(channel_events)

    filtered_route_states = routes.filter_acceptable_routes(
        route_states=payment_state.routes, blacklisted_channel_ids=payment_state.cancelled_channels
    )

    old_description = initiator_state.transfer_description
    transfer_description = TransferDescriptionWithSecretState(
        payment_network_identifier=old_description.payment_network_identifier,
        payment_identifier=old_description.payment_identifier,
        payment_hash_invoice=old_description.payment_hash_invoice,
        amount=old_description.amount,
        token_network_identifier=old_description.token_network_identifier,
        allocated_fee=old_description.allocated_fee,
        initiator=old_description.initiator,
        target=old_description.target,
        secret=state_change.secret,
    )

    sub_iteration = maybe_try_new_route(
        payment_state=payment_state,
        initiator_state=initiator_state,
        transfer_description=transfer_description,
        available_routes=filtered_route_states,
        channelidentifiers_to_channels=channelidentifiers_to_channels,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    events.extend(sub_iteration.events)

    if sub_iteration.new_state is None:
        # Here we don't delete the initiator state, but instead let it live.
        # It will be deleted when the lock expires. We do that so that we
        # still have an initiator payment task around to process the
        # LockExpired message that our partner will send us.
        # https://github.com/raiden-network/raiden/issues/3146#issuecomment-447378046
        return TransitionResult(payment_state, events)

    return TransitionResult(payment_state, events)


def handle_lock_expired(
    payment_state: InitiatorPaymentState,
    state_change: ReceiveLockExpired,
    channelidentifiers_to_channels: ChannelMap,
    block_number: BlockNumber,
) -> TransitionResult[InitiatorPaymentState]:
    """Initiator also needs to handle LockExpired messages when refund transfers are involved.

    A -> B -> C

    - A sends locked transfer to B
    - B attempted to forward to C but has not enough capacity
    - B sends a refund transfer with the same secrethash back to A
    - When the lock expires B will also send a LockExpired message to A
    - A needs to be able to properly process it

    Related issue: https://github.com/raiden-network/raiden/issues/3183
"""
    initiator_state = payment_state.initiator_transfers.get(state_change.secrethash)
    if not initiator_state:
        return TransitionResult(payment_state, list())

    channel_identifier = initiator_state.channel_identifier
    try:
        channel_state = channelidentifiers_to_channels[
            initiator_state.transfer_description.initiator].get(channel_identifier)
    except KeyError:
        return TransitionResult(payment_state, list())

    secrethash = initiator_state.transfer.lock.secrethash
    result = channel.handle_receive_lock_expired(
        channel_state=channel_state, state_change=state_change, block_number=block_number
    )
    assert result.new_state, "handle_receive_lock_expired should not delete the task"

    if not channel.get_lock(result.new_state.partner_state, secrethash):
        transfer = initiator_state.transfer
        unlock_failed = EventUnlockClaimFailed(
            identifier=transfer.payment_identifier,
            secrethash=transfer.lock.secrethash,
            reason="Lock expired",
        )
        result.events.append(unlock_failed)

    return TransitionResult(payment_state, result.events)



def handle_offchain_secretreveal_light(
    payment_state: InitiatorPaymentState,
    state_change: ReceiveSecretRevealLight,
    channelidentifiers_to_channels: ChannelMap,
    pseudo_random_generator: random.Random,
) -> TransitionResult:
    initiator_state = payment_state.initiator_transfers.get(state_change.secrethash)

    if not initiator_state:
        return TransitionResult(payment_state, list())

    assert initiator_state.transfer_state != "transfer_cancelled"

    sub_iteration = subdispatch_to_initiatortransfer(
        payment_state=payment_state,
        initiator_state=initiator_state,
        state_change=state_change,
        channelidentifiers_to_channels=channelidentifiers_to_channels,
        pseudo_random_generator=pseudo_random_generator,
    )

    # The current secretreveal unlocked the transfer
    if not transfer_exists(payment_state, state_change.secrethash):
        cancel_other_transfers(payment_state)

    return TransitionResult(payment_state, sub_iteration.events)


def handle_offchain_secretreveal(
    payment_state: InitiatorPaymentState,
    state_change: ReceiveSecretReveal,
    channelidentifiers_to_channels: ChannelMap,
    pseudo_random_generator: random.Random,
) -> TransitionResult:
    initiator_state = payment_state.initiator_transfers.get(state_change.secrethash)

    if not initiator_state:
        return TransitionResult(payment_state, list())

    assert initiator_state.transfer_state != "transfer_cancelled"

    sub_iteration = subdispatch_to_initiatortransfer(
        payment_state=payment_state,
        initiator_state=initiator_state,
        state_change=state_change,
        channelidentifiers_to_channels=channelidentifiers_to_channels,
        pseudo_random_generator=pseudo_random_generator,
    )

    # The current secretreveal unlocked the transfer
    if not transfer_exists(payment_state, state_change.secrethash):
        cancel_other_transfers(payment_state)

    return TransitionResult(payment_state, sub_iteration.events)


def handle_onchain_secretreveal(
    payment_state: InitiatorPaymentState,
    state_change: ContractReceiveSecretReveal,
    channelidentifiers_to_channels: ChannelMap,
    pseudo_random_generator: random.Random,
) -> TransitionResult[InitiatorPaymentState]:
    initiator_state = payment_state.initiator_transfers.get(state_change.secrethash)

    if not initiator_state:
        return TransitionResult(payment_state, list())

    assert initiator_state.transfer_state != "transfer_cancelled"

    sub_iteration = subdispatch_to_initiatortransfer(
        payment_state=payment_state,
        initiator_state=initiator_state,
        state_change=state_change,
        channelidentifiers_to_channels=channelidentifiers_to_channels,
        pseudo_random_generator=pseudo_random_generator,
    )

    # The current secretreveal unlocked the transfer
    if not transfer_exists(payment_state, state_change.secrethash):
        cancel_other_transfers(payment_state)

    return TransitionResult(payment_state, sub_iteration.events)


def handle_secretrequest(
    payment_state: InitiatorPaymentState,
    state_change: ReceiveSecretRequest,
    channelidentifiers_to_channels: ChannelMap,
    pseudo_random_generator: random.Random,
) -> TransitionResult[InitiatorPaymentState]:
    initiator_state = payment_state.initiator_transfers.get(state_change.secrethash)

    if not initiator_state:
        return TransitionResult(payment_state, list())

    if initiator_state.transfer_state == "transfer_cancelled":
        return TransitionResult(payment_state, list())

    sub_iteration = subdispatch_to_initiatortransfer(
        payment_state=payment_state,
        initiator_state=initiator_state,
        state_change=state_change,
        channelidentifiers_to_channels=channelidentifiers_to_channels,
        pseudo_random_generator=pseudo_random_generator,
    )

    return TransitionResult(payment_state, sub_iteration.events)


def handle_send_secret_reveal_light(
    payment_state: InitiatorPaymentState,
    state_change: ActionSendSecretRevealLight,
    channelidentifiers_to_channels: ChannelMap,
    pseudo_random_generator: random.Random,
) -> TransitionResult[InitiatorPaymentState]:
    secrethash = keccak(state_change.reveal_secret.secret)

    initiator_state = payment_state.initiator_transfers.get(secrethash)

    if not initiator_state:
        return TransitionResult(payment_state, list())

    if initiator_state.transfer_state == "transfer_cancelled":
        return TransitionResult(payment_state, list())

    sub_iteration = subdispatch_to_initiatortransfer(
        payment_state=payment_state,
        initiator_state=initiator_state,
        state_change=state_change,
        channelidentifiers_to_channels=channelidentifiers_to_channels,
        pseudo_random_generator=pseudo_random_generator,
    )

    return TransitionResult(payment_state, sub_iteration.events)


def handle_secretrequest_light(
    payment_state: InitiatorPaymentState,
    state_change: ReceiveSecretRequestLight,
    channelidentifiers_to_channels: ChannelMap,
    pseudo_random_generator: random.Random,
) -> TransitionResult[InitiatorPaymentState]:
    initiator_state = payment_state.initiator_transfers.get(state_change.secrethash)

    if not initiator_state:
        return TransitionResult(payment_state, list())

    if initiator_state.transfer_state == "transfer_cancelled":
        return TransitionResult(payment_state, list())

    sub_iteration = subdispatch_to_initiatortransfer(
        payment_state=payment_state,
        initiator_state=initiator_state,
        state_change=state_change,
        channelidentifiers_to_channels=channelidentifiers_to_channels,
        pseudo_random_generator=pseudo_random_generator,
    )

    return TransitionResult(payment_state, sub_iteration.events)


def handle_secretreveal_light(
    payment_state: InitiatorPaymentState,
    state_change: ReceiveSecretRequestLight,
    channelidentifiers_to_channels: ChannelMap,
    pseudo_random_generator: random.Random,
) -> TransitionResult[InitiatorPaymentState]:
    initiator_state = payment_state.initiator_transfers.get(state_change.secrethash)

    if not initiator_state:
        return TransitionResult(payment_state, list())

    if initiator_state.transfer_state == "transfer_cancelled":
        return TransitionResult(payment_state, list())

    sub_iteration = subdispatch_to_initiatortransfer(
        payment_state=payment_state,
        initiator_state=initiator_state,
        state_change=state_change,
        channelidentifiers_to_channels=channelidentifiers_to_channels,
        pseudo_random_generator=pseudo_random_generator,
    )

    return TransitionResult(payment_state, sub_iteration.events)


def handle_store_refund_transfer_light(payment_state: InitiatorPaymentState,
                                       refund_transfer: RefundTransfer
                                       ) -> TransitionResult[InitiatorPaymentState]:
    order = 1
    store_refund_transfer = StoreMessageEvent(refund_transfer.message_identifier,
                                              refund_transfer.payment_identifier,
                                              order,
                                              refund_transfer,
                                              True,
                                              LightClientProtocolMessageType.PaymentRefund, refund_transfer.recipient)
    return TransitionResult(payment_state, [store_refund_transfer])



def state_transition(
    payment_state: Optional[InitiatorPaymentState],
    state_change: StateChange,
    channelidentifiers_to_channels: ChannelMap,
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
    storage=None
) -> TransitionResult[InitiatorPaymentState]:
    # pylint: disable=unidiomatic-typecheck
    if type(state_change) == Block:
        assert isinstance(state_change, Block), MYPY_ANNOTATION
        assert payment_state, "Block state changes should be accompanied by a valid payment state"
        iteration = handle_block(
            payment_state=payment_state,
            state_change=state_change,
            channelidentifiers_to_channels=channelidentifiers_to_channels,
            pseudo_random_generator=pseudo_random_generator,
        )
    elif type(state_change) == ActionInitInitiator:
        assert isinstance(state_change, ActionInitInitiator), MYPY_ANNOTATION
        iteration = handle_init(
            payment_state=payment_state,
            state_change=state_change,
            channelidentifiers_to_channels=channelidentifiers_to_channels,
            pseudo_random_generator=pseudo_random_generator,
            block_number=block_number,
        )
    elif type(state_change) == ActionInitInitiatorLight:
        assert isinstance(state_change, ActionInitInitiatorLight), MYPY_ANNOTATION
        iteration = handle_init_light(
            payment_state=payment_state,
            state_change=state_change,
            channelidentifiers_to_channels=channelidentifiers_to_channels
        )
    elif type(state_change) == ReceiveTransferCancelRoute:
        assert isinstance(state_change, ReceiveTransferCancelRoute), MYPY_ANNOTATION
        assert (
            payment_state
        ), "ReceiveTransferCancelRoute should be accompanied by a valid payment state"
        iteration = handle_failroute(payment_state=payment_state, state_change=state_change)
    elif type(state_change) == ReceiveSecretRequest:
        assert isinstance(state_change, ReceiveSecretRequest), MYPY_ANNOTATION
        assert payment_state, "ReceiveSecretRequest should be accompanied by a valid payment state"
        iteration = handle_secretrequest(
            payment_state=payment_state,
            state_change=state_change,
            channelidentifiers_to_channels=channelidentifiers_to_channels,
            pseudo_random_generator=pseudo_random_generator,
        )
    elif type(state_change) == ReceiveSecretRequestLight:
        assert isinstance(state_change, ReceiveSecretRequestLight), MYPY_ANNOTATION
        assert payment_state, "ReceiveSecretRequestLight should be accompanied by a valid payment state"
        iteration = handle_secretrequest_light(
            payment_state=payment_state,
            state_change=state_change,
            channelidentifiers_to_channels=channelidentifiers_to_channels,
            pseudo_random_generator=pseudo_random_generator,
        )
    elif type(state_change) == ActionSendSecretRevealLight:
        assert isinstance(state_change, ActionSendSecretRevealLight), MYPY_ANNOTATION
        assert payment_state, "ActionSendSecretRevealLight should be accompanied by a valid payment state"
        iteration = handle_send_secret_reveal_light(
            payment_state=payment_state,
            state_change=state_change,
            channelidentifiers_to_channels=channelidentifiers_to_channels,
            pseudo_random_generator=pseudo_random_generator,
        )
    elif type(state_change) == ActionTransferReroute:
        assert isinstance(state_change, ActionTransferReroute), MYPY_ANNOTATION
        msg = "ActionTransferReroute should be accompanied by a valid payment state"
        assert payment_state, msg
        iteration = handle_transferreroute(
            payment_state=payment_state,
            state_change=state_change,
            channelidentifiers_to_channels=channelidentifiers_to_channels,
            pseudo_random_generator=pseudo_random_generator,
            block_number=block_number,
            storage=storage,
        )
    elif type(state_change) == ActionCancelPayment:
        assert isinstance(state_change, ActionCancelPayment), MYPY_ANNOTATION
        assert payment_state, "ActionCancelPayment should be accompanied by a valid payment state"
        iteration = handle_cancelpayment(
            payment_state=payment_state,
            channelidentifiers_to_channels=channelidentifiers_to_channels,
        )
    elif type(state_change) == ReceiveSecretReveal:
        assert isinstance(state_change, ReceiveSecretReveal), MYPY_ANNOTATION
        assert payment_state, "ReceiveSecretReveal should be accompanied by a valid payment state"
        iteration = handle_offchain_secretreveal(
            payment_state=payment_state,
            state_change=state_change,
            channelidentifiers_to_channels=channelidentifiers_to_channels,
            pseudo_random_generator=pseudo_random_generator,
        )
    elif type(state_change) == ReceiveSecretRevealLight:
        assert isinstance(state_change, ReceiveSecretRevealLight), MYPY_ANNOTATION
        assert payment_state, "ReceiveSecretRevealLight should be accompanied by a valid payment state"
        iteration = handle_offchain_secretreveal_light(
            payment_state=payment_state,
            state_change=state_change,
            channelidentifiers_to_channels=channelidentifiers_to_channels,
            pseudo_random_generator=pseudo_random_generator,
        )
    elif type(state_change) == ReceiveLockExpired:
        assert isinstance(state_change, ReceiveLockExpired), MYPY_ANNOTATION
        assert payment_state, "ReceiveLockExpired should be accompanied by a valid payment state"
        iteration = handle_lock_expired(
            payment_state=payment_state,
            state_change=state_change,
            channelidentifiers_to_channels=channelidentifiers_to_channels,
            block_number=block_number,
        )
    elif type(state_change) == ContractReceiveSecretReveal:
        assert isinstance(state_change, ContractReceiveSecretReveal), MYPY_ANNOTATION
        msg = "ContractReceiveSecretReveal should be accompanied by a valid payment state"
        assert payment_state, msg
        iteration = handle_onchain_secretreveal(
            payment_state=payment_state,
            state_change=state_change,
            channelidentifiers_to_channels=channelidentifiers_to_channels,
            pseudo_random_generator=pseudo_random_generator,
        )
    elif type(state_change) == StoreRefundTransferLight:
        assert isinstance(state_change, StoreRefundTransferLight), MYPY_ANNOTATION
        assert payment_state, "StoreRefundTransferLight should be accompanied by a valid payment state"
        iteration = handle_store_refund_transfer_light(payment_state=payment_state, refund_transfer=state_change.transfer)
    else:
        iteration = TransitionResult(payment_state, list())

    return clear_if_finalized(iteration)
