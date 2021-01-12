from raiden.lightclient.models.light_client_protocol_message import LightClientProtocolMessageType
from raiden.transfer import channel, token_network, views
from raiden.transfer.architecture import (
    ContractReceiveStateChange,
    ContractSendEvent,
    Event,
    SendMessageEvent,
    StateChange,
    TransitionResult,
)
from raiden.transfer.events import (
    ContractSendChannelBatchUnlock,
    ContractSendChannelClose,
    ContractSendChannelSettle,
    ContractSendChannelUpdateTransfer,
    ContractSendSecretReveal,
)
from raiden.transfer.identifiers import CanonicalIdentifier, QueueIdentifier
from raiden.transfer.mediated_transfer import initiator_manager, mediator, target
from raiden.transfer.mediated_transfer.events import CHANNEL_IDENTIFIER_GLOBAL_QUEUE, StoreMessageEvent, \
    SendLockExpiredLight
from raiden.transfer.mediated_transfer.state import (
    InitiatorPaymentState,
    MediatorTransferState,
    TargetTransferState,
)
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitInitiator,
    ActionInitMediator,
    ActionInitTarget,
    ReceiveLockExpired,
    ReceiveSecretRequest,
    ReceiveSecretReveal,
    ReceiveTransferRefund,
    ActionTransferReroute,
    ActionInitInitiatorLight, ReceiveSecretRequestLight, ActionSendSecretRevealLight, ReceiveSecretRevealLight,
    ActionSendUnlockLight, ActionInitTargetLight, ActionSendSecretRequestLight, ActionSendLockExpiredLight,
    ReceiveLockExpiredLight, ReceiveTransferCancelRoute,
    StoreRefundTransferLight)
from raiden.transfer.state import (
    ChainState,
    InitiatorTask,
    MediatorTask,
    PaymentNetworkState,
    TargetTask,
    TokenNetworkState,
    LightClientTransportState,
    NodeTransportState)
from raiden.transfer.state_change import (
    ActionChangeNodeNetworkState,
    ActionChannelClose,
    ActionChannelSetFee,
    ActionInitChain,
    ActionLeaveAllNetworks,
    ActionNewTokenNetwork,
    ActionUpdateTransportAuthData,
    Block,
    ContractReceiveChannelBatchUnlock,
    ContractReceiveChannelClosed,
    ContractReceiveChannelNew,
    ContractReceiveChannelNewBalance,
    ContractReceiveChannelSettled,
    ContractReceiveNewPaymentNetwork,
    ContractReceiveNewTokenNetwork,
    ContractReceiveRouteClosed,
    ContractReceiveRouteNew,
    ContractReceiveSecretReveal,
    ContractReceiveSecretRevealLight,
    ContractReceiveUpdateTransfer,
    ReceiveDelivered,
    ReceiveProcessed,
    ReceiveUnlock,
    ReceiveUnlockLight, ContractReceiveChannelClosedLight, ContractReceiveChannelSettledLight)

from raiden.utils.typing import (
    MYPY_ANNOTATION,
    BlockHash,
    BlockNumber,
    ChannelID,
    List,
    Optional,
    PaymentNetworkID,
    SecretHash,
    TokenAddress,
    TokenNetworkAddress,
    TokenNetworkID,
    Tuple,
    Union,
    Address, AddressHex)

from eth_utils import to_canonical_address

import structlog

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name

# All State changes that are subdispatched as token network actions
TokenNetworkStateChange = Union[
    ActionChannelClose,
    ContractReceiveChannelBatchUnlock,
    ContractReceiveChannelNew,
    ContractReceiveChannelNewBalance,
    ContractReceiveChannelSettled,
    ContractReceiveRouteNew,
    ContractReceiveRouteClosed,
    ContractReceiveUpdateTransfer,
    ContractReceiveChannelClosed,
]


def get_networks(
    chain_state: ChainState,
    payment_network_identifier: PaymentNetworkID,
    token_address: TokenAddress,
) -> Tuple[Optional[PaymentNetworkState], Optional[TokenNetworkState]]:
    token_network_state = None
    payment_network_state = chain_state.identifiers_to_paymentnetworks.get(
        payment_network_identifier
    )

    if payment_network_state:
        token_network_id = payment_network_state.tokenaddresses_to_tokenidentifiers.get(
            token_address
        )

        if token_network_id:
            token_network_state = payment_network_state.tokenidentifiers_to_tokennetworks.get(
                token_network_id
            )

    return payment_network_state, token_network_state


def get_token_network_by_address(
    chain_state: ChainState, token_network_address: Union[TokenNetworkID, TokenNetworkAddress]
) -> Optional[TokenNetworkState]:
    payment_network_identifier = chain_state.tokennetworkaddresses_to_paymentnetworkaddresses.get(
        TokenNetworkAddress(token_network_address)
    )

    payment_network_state = None
    if payment_network_identifier:
        payment_network_state = chain_state.identifiers_to_paymentnetworks.get(
            payment_network_identifier
        )

    token_network_state = None
    if payment_network_state:
        token_network_state = payment_network_state.tokenidentifiers_to_tokennetworks.get(
            TokenNetworkID(token_network_address)
        )

    return token_network_state


def subdispatch_to_all_channels(
    chain_state: ChainState,
    state_change: StateChange,
    block_number: BlockNumber,
    block_hash: BlockHash,
) -> TransitionResult[ChainState]:
    events = list()

    for payment_network in chain_state.identifiers_to_paymentnetworks.values():
        for token_network_state in payment_network.tokenidentifiers_to_tokennetworks.values():
            for client in token_network_state.channelidentifiers_to_channels:
                for channel_state in token_network_state.channelidentifiers_to_channels[client].values():
                    result = channel.state_transition(
                        channel_state=channel_state,
                        state_change=state_change,
                        block_number=block_number,
                        block_hash=block_hash,
                    )
                    events.extend(result.events)

    return TransitionResult(chain_state, events)


def subdispatch_by_canonical_id(
    chain_state: ChainState, canonical_identifier: CanonicalIdentifier, state_change: StateChange
) -> TransitionResult[ChainState]:
    token_network_state = get_token_network_by_address(
        chain_state, canonical_identifier.token_network_address
    )

    events: List[Event] = list()
    if token_network_state:
        iteration = token_network.state_transition(
            token_network_state=token_network_state,
            state_change=state_change,
            block_number=chain_state.block_number,
            block_hash=chain_state.block_hash,
        )
        assert iteration.new_state, "No token network state transition can lead to None"

        events = iteration.events

    return TransitionResult(chain_state, events)


def subdispatch_to_all_lockedtransfers(
    chain_state: ChainState, state_change: StateChange, storage=None
) -> TransitionResult[ChainState]:
    events = list()
    for node_address, payment_state in chain_state.get_payment_states_by_address():
        for secrethash in list(payment_state.secrethashes_to_task):
            result = subdispatch_to_paymenttask(chain_state, state_change, node_address, secrethash, storage)
            events.extend(result.events)
    return TransitionResult(chain_state, events)


def subdispatch_to_paymenttask(
    chain_state: ChainState, state_change: StateChange, node_address: AddressHex, secrethash: SecretHash, storage=None
) -> TransitionResult[ChainState]:
    block_number = chain_state.block_number
    block_hash = chain_state.block_hash
    sub_task = chain_state.get_payment_task(node_address, secrethash)

    events: List[Event] = list()
    if sub_task:
        pseudo_random_generator = chain_state.pseudo_random_generator
        sub_iteration: Union[
            TransitionResult[InitiatorPaymentState],
            TransitionResult[MediatorTransferState],
            TransitionResult[TargetTransferState],
        ]

        if isinstance(sub_task, InitiatorTask):
            token_network_identifier = sub_task.token_network_identifier
            token_network_state = get_token_network_by_address(
                chain_state, token_network_identifier
            )
            if token_network_state:
                sub_iteration = initiator_manager.state_transition(
                    sub_task.manager_state,
                    state_change,
                    token_network_state.channelidentifiers_to_channels,
                    pseudo_random_generator,
                    block_number,
                    storage,
                )
                events = sub_iteration.events
                if sub_iteration.new_state is None:
                    chain_state.delete_payment_task(node_address, secrethash)

        elif isinstance(sub_task, MediatorTask):
            token_network_identifier = sub_task.token_network_identifier
            token_network_state = get_token_network_by_address(
                chain_state, token_network_identifier
            )

            if token_network_state:
                channelids_to_channels = token_network_state.channelidentifiers_to_channels.get(chain_state.our_address)
                sub_iteration = mediator.state_transition(
                    mediator_state=sub_task.mediator_state,
                    state_change=state_change,
                    channelidentifiers_to_channels=channelids_to_channels,
                    nodeaddresses_to_networkstates=chain_state.nodeaddresses_to_networkstates,
                    pseudo_random_generator=pseudo_random_generator,
                    block_number=block_number,
                    block_hash=block_hash,
                    storage=storage
                )
                events = sub_iteration.events

                if sub_iteration.new_state is None:
                    chain_state.delete_payment_task(node_address, secrethash)

        elif isinstance(sub_task, TargetTask):
            token_network_identifier = sub_task.token_network_identifier
            channel_identifier = sub_task.channel_identifier

            channel_state = views.get_channelstate_by_canonical_identifier_and_address(
                chain_state=chain_state,
                canonical_identifier=CanonicalIdentifier(
                    chain_identifier=chain_state.chain_id,
                    token_network_address=token_network_identifier,
                    channel_identifier=channel_identifier,
                ),
                address=sub_task.target_state.transfer.target
            )

            if channel_state:
                sub_iteration = target.state_transition(
                    target_state=sub_task.target_state,
                    state_change=state_change,
                    channel_state=channel_state,
                    pseudo_random_generator=pseudo_random_generator,
                    block_number=block_number,
                    storage=storage
                )
                events = sub_iteration.events

                if sub_iteration.new_state is None:
                    chain_state.delete_payment_task(node_address, secrethash)

    return TransitionResult(chain_state, events)


def handle_init_unlock_light(
    chain_state: ChainState, state_change: ActionSendUnlockLight
) -> TransitionResult[ChainState]:
    channel_state = views.get_channelstate_by_canonical_identifier_and_address(
        chain_state=chain_state,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=chain_state.chain_id,
            token_network_address=state_change.unlock.token_network_address,
            channel_identifier=state_change.unlock.channel_identifier,
        ),
        address=state_change.sender
    )
    events = list()
    if channel_state:
        balance_proof = channel.create_send_balance_proof_light(channel_state, state_change.unlock,
                                                                state_change.sender, state_change.receiver)
        store_signed_bp = StoreMessageEvent(message_id=balance_proof.message_identifier,
                                            payment_id=balance_proof.payment_identifier,
                                            message_order=11,
                                            message=state_change.unlock,
                                            is_signed=True,
                                            message_type=LightClientProtocolMessageType.PaymentSuccessful,
                                            light_client_address=balance_proof.sender)
        events.append(balance_proof)
        events.append(store_signed_bp)
    return TransitionResult(chain_state, events)


def handle_init_send_lock_expired_light(
    chain_state: ChainState, state_change: ActionSendLockExpiredLight
) -> TransitionResult[ChainState]:
    signed_lock_expired = state_change.signed_lock_expired
    send_lock_expired_light = SendLockExpiredLight(state_change.receiver, signed_lock_expired.message_identifier,
                                                   signed_lock_expired, state_change.signed_lock_expired.secrethash,
                                                   state_change.payment_id)
    store_lock_expired_light = StoreMessageEvent(message_id=signed_lock_expired.message_identifier,
                                                 payment_id=state_change.payment_id,
                                                 message_order=1,
                                                 message=signed_lock_expired,
                                                 is_signed=True,
                                                 message_type=LightClientProtocolMessageType.PaymentExpired,
                                                 light_client_address=signed_lock_expired.sender)
    events = [send_lock_expired_light, store_lock_expired_light]
    return TransitionResult(chain_state, events)


def handle_store_refund_transfer_light(chain_state: ChainState,
                                       state_change: StoreRefundTransferLight) -> TransitionResult[ChainState]:
    return subdispatch_to_paymenttask(chain_state,
                                      state_change,
                                      state_change.transfer.initiator,
                                      state_change.transfer.lock.secrethash)


def subdispatch_initiatortask(
    chain_state: ChainState,
    state_change: StateChange,
    token_network_identifier: TokenNetworkID,
    node_address: AddressHex,
    secrethash: SecretHash,
) -> TransitionResult[ChainState]:
    block_number = chain_state.block_number
    sub_task = chain_state.get_payment_task(node_address, secrethash)

    if not sub_task:
        is_valid_subtask = True
        manager_state = None

    elif sub_task and isinstance(sub_task, InitiatorTask):
        is_valid_subtask = token_network_identifier == sub_task.token_network_identifier
        manager_state = sub_task.manager_state
    else:
        is_valid_subtask = False

    events: List[Event] = list()
    if is_valid_subtask:
        pseudo_random_generator = chain_state.pseudo_random_generator

        token_network_state = get_token_network_by_address(chain_state, token_network_identifier)

        if token_network_state:
            iteration = initiator_manager.state_transition(
                payment_state=manager_state,
                state_change=state_change,
                channelidentifiers_to_channels=token_network_state.channelidentifiers_to_channels,
                pseudo_random_generator=pseudo_random_generator,
                block_number=block_number,
            )
            events = iteration.events

            if iteration.new_state:
                sub_task = InitiatorTask(token_network_identifier, iteration.new_state)
                chain_state.create_payment_task(node_address, secrethash, sub_task)
            elif chain_state.get_payment_task(node_address, secrethash) and \
                not isinstance(state_change, ActionInitInitiatorLight):
                # We dont delete the payment task when is a light payment,
                # thats because we need the previous payment task for refunds.
                # TODO marcosmartinez7, are the p2p payments being removed?
                chain_state.delete_payment_task(node_address, secrethash)
                log.info(f"Deleted payment task for address {node_address} and secret hash {secrethash.hex()}")

    return TransitionResult(chain_state, events)


def subdispatch_mediatortask(
    chain_state: ChainState,
    state_change: StateChange,
    token_network_identifier: TokenNetworkID,
    node_address: AddressHex,
    secrethash: SecretHash,
    storage=None
) -> TransitionResult[ChainState]:
    block_number = chain_state.block_number
    block_hash = chain_state.block_hash
    sub_task = chain_state.get_payment_task(node_address, secrethash)
    if not sub_task:
        is_valid_subtask = True
        mediator_state = None

    elif sub_task and isinstance(sub_task, MediatorTask):
        is_valid_subtask = token_network_identifier == sub_task.token_network_identifier
        mediator_state = sub_task.mediator_state
    else:
        is_valid_subtask = False

    events: List[Event] = list()
    if is_valid_subtask:
        token_network_state = get_token_network_by_address(chain_state, token_network_identifier)

        if token_network_state:
            pseudo_random_generator = chain_state.pseudo_random_generator
            iteration = mediator.state_transition(
                mediator_state=mediator_state,
                state_change=state_change,
                channelidentifiers_to_channels=token_network_state.channelidentifiers_to_channels.get(
                    chain_state.our_address),
                nodeaddresses_to_networkstates=chain_state.nodeaddresses_to_networkstates,
                pseudo_random_generator=pseudo_random_generator,
                block_number=block_number,
                block_hash=block_hash,
                storage=storage
            )
            events = iteration.events

            if iteration.new_state:
                sub_task = MediatorTask(token_network_identifier, iteration.new_state)
                chain_state.create_payment_task(node_address, secrethash, sub_task)
            elif chain_state.get_payment_task(node_address, secrethash):
                chain_state.delete_payment_task(node_address, secrethash)

    return TransitionResult(chain_state, events)


def subdispatch_targettask(
    chain_state: ChainState,
    state_change: StateChange,
    token_network_identifier: TokenNetworkID,
    channel_identifier: ChannelID,
    node_address: AddressHex,
    secrethash: SecretHash,
    initiator: AddressHex,
    storage
) -> TransitionResult[ChainState]:
    block_number = chain_state.block_number
    sub_task = chain_state.get_payment_task(node_address, secrethash)
    if not sub_task:
        is_valid_subtask = True
        target_state = None

    elif sub_task and isinstance(sub_task, TargetTask):
        is_valid_subtask = token_network_identifier == sub_task.token_network_identifier
        target_state = sub_task.target_state
    else:
        is_valid_subtask = False

    events: List[Event] = list()
    channel_state = None
    if is_valid_subtask:
        channel_state = views.get_channelstate_by_canonical_identifier_and_address(
            chain_state=chain_state,
            canonical_identifier=CanonicalIdentifier(
                chain_identifier=chain_state.chain_id,
                token_network_address=token_network_identifier,
                channel_identifier=channel_identifier,
            ),
            address=initiator
        )

    if channel_state:
        pseudo_random_generator = chain_state.pseudo_random_generator

        iteration = target.state_transition(
            target_state=target_state,
            state_change=state_change,
            channel_state=channel_state,
            pseudo_random_generator=pseudo_random_generator,
            block_number=block_number,
            storage=storage
        )
        events = iteration.events

        if iteration.new_state:
            sub_task = TargetTask(channel_state.canonical_identifier, iteration.new_state)
            chain_state.create_payment_task(node_address, secrethash, sub_task)
        elif chain_state.get_payment_task(node_address, secrethash):
            chain_state.delete_payment_task(node_address, secrethash)

    return TransitionResult(chain_state, events)


def maybe_add_tokennetwork(
    chain_state: ChainState,
    payment_network_identifier: PaymentNetworkID,
    token_network_state: TokenNetworkState,
) -> None:
    token_network_identifier = token_network_state.address
    token_address = token_network_state.token_address

    payment_network_state, token_network_state_previous = get_networks(
        chain_state, payment_network_identifier, token_address
    )

    if payment_network_state is None:
        payment_network_state = PaymentNetworkState(
            payment_network_identifier, [token_network_state]
        )

        ids_to_payments = chain_state.identifiers_to_paymentnetworks
        ids_to_payments[payment_network_identifier] = payment_network_state

    if token_network_state_previous is None:
        ids_to_tokens = payment_network_state.tokenidentifiers_to_tokennetworks
        addresses_to_ids = payment_network_state.tokenaddresses_to_tokenidentifiers

        ids_to_tokens[token_network_identifier] = token_network_state
        addresses_to_ids[token_address] = token_network_identifier

        mapping = chain_state.tokennetworkaddresses_to_paymentnetworkaddresses
        # FIXME: Remove cast once TokenNetworkAddress or TokenNetworkID are removed
        mapping[TokenNetworkAddress(token_network_identifier)] = payment_network_identifier


def sanity_check(iteration: TransitionResult[ChainState]) -> None:
    assert isinstance(iteration.new_state, ChainState)


def inplace_delete_message_queue(
    chain_state: ChainState,
    state_change: Union[ReceiveDelivered, ReceiveProcessed],
    queueid: QueueIdentifier,
) -> None:
    """ Filter messages from queue, if the queue becomes empty, cleanup the queue itself. """
    queue = chain_state.queueids_to_queues.get(queueid)
    if not queue:
        return

    inplace_delete_message(message_queue=queue, state_change=state_change)

    if len(queue) == 0:
        del chain_state.queueids_to_queues[queueid]
    else:
        chain_state.queueids_to_queues[queueid] = queue


def inplace_delete_message(
    message_queue: List[SendMessageEvent], state_change: Union[ReceiveDelivered, ReceiveProcessed]
) -> None:
    """ Check if the message exists in queue with ID `queueid` and exclude if found."""
    for message in list(message_queue):
        message_found = (
            message.message_identifier == state_change.message_identifier
            and message.recipient == state_change.sender
        )
        if message_found:
            message_queue.remove(message)


def handle_block(chain_state: ChainState, state_change: Block, storage=None) -> TransitionResult[ChainState]:
    block_number = state_change.block_number
    chain_state.block_number = block_number
    chain_state.block_hash = state_change.block_hash

    # Subdispatch Block state change
    channels_result = subdispatch_to_all_channels(
        chain_state=chain_state,
        state_change=state_change,
        block_number=block_number,
        block_hash=chain_state.block_hash,
    )
    transfers_result = subdispatch_to_all_lockedtransfers(chain_state, state_change, storage)
    events = channels_result.events + transfers_result.events
    return TransitionResult(chain_state, events)


def handle_chain_init(
    chain_state: ChainState, state_change: ActionInitChain
) -> TransitionResult[ChainState]:
    if chain_state is None:
        chain_state = ChainState(
            pseudo_random_generator=state_change.pseudo_random_generator,
            block_number=state_change.block_number,
            block_hash=state_change.block_hash,
            our_address=state_change.our_address,
            chain_id=state_change.chain_id,
        )
    events: List[Event] = list()
    return TransitionResult(chain_state, events)


def handle_token_network_action(
    chain_state: ChainState, state_change: TokenNetworkStateChange
) -> TransitionResult[ChainState]:
    token_network_state = get_token_network_by_address(
        chain_state, state_change.token_network_identifier
    )

    events: List[Event] = list()
    if token_network_state:
        iteration = token_network.state_transition(
            token_network_state=token_network_state,
            state_change=state_change,
            block_number=chain_state.block_number,
            block_hash=chain_state.block_hash,
        )

        # TODO marcosmartinez7 take a look at this
        # Investigate behavior of this @GASPAR MEDINA
        # assert iteration.new_state, "No token network state transition leads to None"

        events = []
        if iteration is not None:
            events = iteration.events

    return TransitionResult(chain_state, events)


def handle_contract_receive_channel_closed(
    chain_state: ChainState,
    state_change: ContractReceiveChannelClosed,
    participant1: AddressHex
) -> TransitionResult[ChainState]:
    cleanup_queue_for_channel(participant1, chain_state, state_change)

    return handle_token_network_action(chain_state=chain_state, state_change=state_change)


def handle_contract_receive_channel_closed_light(
    chain_state: ChainState,
    state_change: ContractReceiveChannelClosedLight
) -> TransitionResult[ChainState]:
    cleanup_queue_for_channel(state_change.closing_participant, chain_state, state_change)
    cleanup_queue_for_channel(state_change.non_closing_participant, chain_state, state_change)

    return handle_token_network_action(chain_state=chain_state, state_change=state_change)


def cleanup_queue_for_channel(participant, chain_state, state_change):
    channel_state = views.get_channelstate_by_canonical_identifier_and_address(
        chain_state=chain_state,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=chain_state.chain_id,
            token_network_address=state_change.token_network_identifier,
            channel_identifier=state_change.channel_identifier,
        ),

        address=participant
    )
    if channel_state:
        queue_id = QueueIdentifier(
            recipient=channel_state.partner_state.address,
            channel_identifier=state_change.channel_identifier,
        )
        if queue_id in chain_state.queueids_to_queues:
            chain_state.queueids_to_queues.pop(queue_id)


def handle_delivered(
    chain_state: ChainState, state_change: ReceiveDelivered
) -> TransitionResult[ChainState]:
    """ Check if the "Delivered" message exists in the global queue and delete if found."""
    queueid = QueueIdentifier(state_change.sender, CHANNEL_IDENTIFIER_GLOBAL_QUEUE)
    inplace_delete_message_queue(chain_state, state_change, queueid)
    return TransitionResult(chain_state, [])


def handle_new_token_network(
    chain_state: ChainState, state_change: ActionNewTokenNetwork
) -> TransitionResult[ChainState]:
    token_network_state = state_change.token_network
    payment_network_identifier = state_change.payment_network_identifier

    maybe_add_tokennetwork(chain_state, payment_network_identifier, token_network_state)

    events: List[Event] = list()
    return TransitionResult(chain_state, events)


def handle_node_change_network_state(
    chain_state: ChainState, state_change: ActionChangeNodeNetworkState, storage=None
) -> TransitionResult[ChainState]:
    events: List[Event] = list()

    chain_state.nodeaddresses_to_networkstates[state_change.node_address] = state_change.network_state

    for payment_state in chain_state.get_payment_states():
        for secrethash, subtask in payment_state.secrethashes_to_task.items():
            if isinstance(subtask, MediatorTask):
                result = subdispatch_mediatortask(
                    chain_state=chain_state,
                    state_change=state_change,
                    node_address=chain_state.our_address,
                    secrethash=secrethash,
                    token_network_identifier=subtask.token_network_identifier,
                    storage=storage
                )
                events.extend(result.events)
    return TransitionResult(chain_state, events)


def handle_leave_all_networks(chain_state: ChainState) -> TransitionResult[ChainState]:
    events = list()

    for payment_network_state in chain_state.identifiers_to_paymentnetworks.values():
        all_token_networks = payment_network_state.tokenidentifiers_to_tokennetworks.values()
        for token_network_state in all_token_networks:
            events.extend(_get_channels_close_events(chain_state, token_network_state))

    return TransitionResult(chain_state, events)


def handle_new_payment_network(
    chain_state: ChainState, state_change: ContractReceiveNewPaymentNetwork
) -> TransitionResult[ChainState]:
    events: List[Event] = list()

    payment_network = state_change.payment_network
    payment_network_identifier = PaymentNetworkID(payment_network.address)
    if payment_network_identifier not in chain_state.identifiers_to_paymentnetworks:
        chain_state.identifiers_to_paymentnetworks[payment_network_identifier] = payment_network

    return TransitionResult(chain_state, events)


def handle_tokenadded(
    chain_state: ChainState, state_change: ContractReceiveNewTokenNetwork
) -> TransitionResult[ChainState]:
    events: List[Event] = list()
    maybe_add_tokennetwork(
        chain_state, state_change.payment_network_identifier, state_change.token_network
    )

    return TransitionResult(chain_state, events)


def handle_secret_reveal_light(
    chain_state: ChainState, state_change: ReceiveSecretRevealLight
) -> TransitionResult[ChainState]:
    return subdispatch_to_paymenttask(chain_state, state_change, state_change.recipient, state_change.secrethash)


def handle_secret_reveal(
    chain_state: ChainState, state_change: ReceiveSecretReveal
) -> TransitionResult[ChainState]:
    return subdispatch_to_paymenttask(chain_state, state_change, chain_state.our_address, state_change.secrethash)


def handle_contract_secret_reveal(
    chain_state: ChainState, state_change: ContractReceiveSecretReveal
) -> TransitionResult[ChainState]:
    return subdispatch_to_paymenttask(chain_state, state_change, chain_state.our_address, state_change.secrethash)


def handle_contract_secret_reveal_light(
    chain_state: ChainState, state_change: ContractReceiveSecretRevealLight
) -> TransitionResult[ChainState]:
    return subdispatch_to_paymenttask(chain_state, state_change, state_change.lc_address, state_change.secrethash)


def handle_init_initiator(
    chain_state: ChainState, state_change: ActionInitInitiator
) -> TransitionResult[ChainState]:
    transfer = state_change.transfer
    secrethash = transfer.secrethash

    return subdispatch_initiatortask(
        chain_state, state_change, transfer.token_network_identifier, chain_state.our_address, secrethash
    )


def handle_init_initiator_light(
    chain_state: ChainState, state_change: ActionInitInitiatorLight
) -> TransitionResult[ChainState]:
    received_transfer = state_change.transfer
    secrethash = received_transfer.secrethash

    return subdispatch_initiatortask(
        chain_state, state_change, received_transfer.token_network_identifier,
        state_change.signed_locked_transfer.sender, secrethash
    )


def handle_init_reveal_secret_light(
    chain_state: ChainState, state_change: ActionSendSecretRevealLight
) -> TransitionResult[ChainState]:
    revealsecret = state_change.reveal_secret
    secrethash = revealsecret.secrethash
    return subdispatch_to_paymenttask(chain_state, state_change, state_change.sender, secrethash)


def handle_init_secret_request_light(
    chain_state: ChainState, state_change: ActionSendSecretRequestLight
) -> TransitionResult[ChainState]:
    secret_request = state_change.secret_request
    secrethash = secret_request.secrethash
    return subdispatch_to_paymenttask(chain_state, state_change, state_change.sender, secrethash)


def handle_init_mediator(
    chain_state: ChainState, state_change: ActionInitMediator, storage=None
) -> TransitionResult[ChainState]:
    transfer = state_change.from_transfer
    secrethash = transfer.lock.secrethash
    token_network_identifier = transfer.balance_proof.token_network_identifier

    return subdispatch_mediatortask(
        chain_state, state_change, TokenNetworkID(token_network_identifier), chain_state.our_address, secrethash,
        storage
    )


def handle_init_target(
    chain_state: ChainState, state_change: ActionInitTarget, storage, initiator: Address
) -> TransitionResult[ChainState]:
    transfer = state_change.transfer
    secrethash = transfer.lock.secrethash
    channel_identifier = transfer.balance_proof.channel_identifier
    token_network_identifier = transfer.balance_proof.token_network_identifier

    return subdispatch_targettask(
        chain_state,
        state_change,
        TokenNetworkID(token_network_identifier),
        channel_identifier,
        state_change.transfer.target,
        secrethash,
        initiator,
        storage
    )


def handle_receive_lock_expired(
    chain_state: ChainState, state_change: ReceiveLockExpired
) -> TransitionResult[ChainState]:
    return subdispatch_to_paymenttask(chain_state, state_change, chain_state.our_address, state_change.secrethash)


def handle_receive_lock_expired_light(
    chain_state: ChainState, state_change: ReceiveLockExpiredLight, storage
) -> TransitionResult[ChainState]:
    return subdispatch_to_paymenttask(chain_state, state_change, state_change.lock_expired.recipient,
                                      state_change.secrethash, storage)


def handle_receive_transfer_refund(
    chain_state: ChainState, state_change: ReceiveTransferRefund
) -> TransitionResult[ChainState]:
    # this state it's only for mediator nodes so the node address here should be always our address
    return subdispatch_to_paymenttask(
        chain_state, state_change, chain_state.our_address, state_change.transfer.lock.secrethash
    )


def handle_receive_transfer_refund_cancel_route(
    chain_state: ChainState, state_change: ActionTransferReroute, storage
) -> TransitionResult[ChainState]:
    new_secret_hash = state_change.secrethash

    chain_state.clone_payment_task(chain_state.our_address, state_change.transfer.lock.secrethash, new_secret_hash)

    return subdispatch_to_paymenttask(chain_state, state_change, chain_state.our_address, new_secret_hash, storage)


def handle_receive_transfer_cancel_route(
    chain_state: ChainState, state_change: ReceiveTransferCancelRoute
) -> TransitionResult[ChainState]:
    return subdispatch_to_paymenttask(
        chain_state, state_change, state_change.transfer.initiator, state_change.transfer.lock.secrethash
    )


def handle_receive_secret_request(
    chain_state: ChainState, state_change: ReceiveSecretRequest
) -> TransitionResult[ChainState]:
    secrethash = state_change.secrethash
    return subdispatch_to_paymenttask(chain_state, state_change, chain_state.our_address, secrethash)


def handle_receive_secret_request_light(
    chain_state: ChainState, state_change: ReceiveSecretRequestLight
) -> TransitionResult[ChainState]:
    secrethash = state_change.secrethash
    return subdispatch_to_paymenttask(chain_state, state_change, state_change.recipient, secrethash)


def handle_processed(
    chain_state: ChainState, state_change: ReceiveProcessed
) -> TransitionResult[ChainState]:
    events: List[Event] = list()
    # Clean up message queue
    for queueid in list(chain_state.queueids_to_queues.keys()):
        inplace_delete_message_queue(chain_state, state_change, queueid)

    return TransitionResult(chain_state, events)


def handle_receive_unlock(
    chain_state: ChainState, state_change: ReceiveUnlock
) -> TransitionResult[ChainState]:
    secrethash = state_change.secrethash
    return subdispatch_to_paymenttask(chain_state, state_change, chain_state.our_address, secrethash)


def handle_receive_unlock_light(
    chain_state: ChainState, state_change: ReceiveUnlockLight
) -> TransitionResult[ChainState]:
    secrethash = state_change.secrethash
    return subdispatch_to_paymenttask(chain_state, state_change, state_change.recipient, secrethash)


def handle_update_transport_authdata(
    chain_state: ChainState, state_change: ActionUpdateTransportAuthData
) -> TransitionResult[ChainState]:
    assert chain_state is not None, "chain_state must be set"

    light_client_transport_state = None

    if state_change.address == b'00000000000000000000' or state_change.address == chain_state.our_address:
        if chain_state.last_node_transport_state_authdata is None:
            chain_state.last_node_transport_state_authdata = NodeTransportState('', [])
        chain_state.last_node_transport_state_authdata.hub_last_transport_authdata = state_change.auth_data
    else:
        if len(chain_state.last_node_transport_state_authdata.clients_last_transport_authdata) == 0:
            light_client_transport_state = \
                LightClientTransportState(to_canonical_address(state_change.address), state_change.auth_data)
            chain_state.last_node_transport_state_authdata \
                .clients_last_transport_authdata.append(light_client_transport_state)
        else:
            for client_last_transport_authdata in \
                chain_state.last_node_transport_state_authdata.clients_last_transport_authdata:
                if to_canonical_address(state_change.address) == client_last_transport_authdata.address:
                    client_last_transport_authdata.auth_data = state_change.auth_data
                else:
                    light_client_transport_state = \
                        LightClientTransportState(to_canonical_address(state_change.address),
                                                  state_change.auth_data)

    if light_client_transport_state:
        chain_state.last_node_transport_state_authdata.clients_last_transport_authdata.append(
            light_client_transport_state)

    return TransitionResult(chain_state, list())


def handle_state_change(
    chain_state: ChainState, state_change: StateChange, storage
) -> TransitionResult[ChainState]:
    if type(state_change) == Block:
        assert isinstance(state_change, Block), MYPY_ANNOTATION
        iteration = handle_block(chain_state, state_change, storage)
    elif type(state_change) == ActionInitChain:
        assert isinstance(state_change, ActionInitChain), MYPY_ANNOTATION
        iteration = handle_chain_init(chain_state, state_change)
        assert iteration.new_state, "The iteration should have created a new state"
        chain_state = iteration.new_state
    elif type(state_change) == ActionNewTokenNetwork:
        assert isinstance(state_change, ActionNewTokenNetwork), MYPY_ANNOTATION
        iteration = handle_new_token_network(chain_state, state_change)
    elif type(state_change) == ActionChannelClose:
        assert isinstance(state_change, ActionChannelClose), MYPY_ANNOTATION
        iteration = handle_token_network_action(chain_state, state_change)
    elif type(state_change) == ActionChannelSetFee:
        assert isinstance(state_change, ActionChannelSetFee), MYPY_ANNOTATION
        iteration = subdispatch_by_canonical_id(
            chain_state=chain_state,
            canonical_identifier=state_change.canonical_identifier,
            state_change=state_change,
        )
    elif type(state_change) == ActionChangeNodeNetworkState:
        assert isinstance(state_change, ActionChangeNodeNetworkState), MYPY_ANNOTATION
        iteration = handle_node_change_network_state(chain_state, state_change)
    elif type(state_change) == ActionLeaveAllNetworks:
        assert isinstance(state_change, ActionLeaveAllNetworks), MYPY_ANNOTATION
        iteration = handle_leave_all_networks(chain_state)
    elif type(state_change) == ActionInitInitiator:
        assert isinstance(state_change, ActionInitInitiator), MYPY_ANNOTATION
        iteration = handle_init_initiator(chain_state, state_change)
    elif type(state_change) == ActionInitMediator:
        assert isinstance(state_change, ActionInitMediator), MYPY_ANNOTATION
        iteration = handle_init_mediator(chain_state, state_change, storage)
    elif type(state_change) == ActionInitTarget:
        assert isinstance(state_change, ActionInitTarget), MYPY_ANNOTATION
        iteration = handle_init_target(chain_state, state_change, storage, chain_state.our_address)
    elif type(state_change) == ActionInitTargetLight:
        assert isinstance(state_change, ActionInitTargetLight), MYPY_ANNOTATION
        iteration = handle_init_target(chain_state, state_change, storage, state_change.transfer.target)
    elif type(state_change) == ActionUpdateTransportAuthData:
        assert isinstance(state_change, ActionUpdateTransportAuthData), MYPY_ANNOTATION
        iteration = handle_update_transport_authdata(chain_state, state_change)
    elif type(state_change) == ReceiveTransferCancelRoute:
        assert isinstance(state_change, ReceiveTransferCancelRoute), MYPY_ANNOTATION
        iteration = handle_receive_transfer_cancel_route(chain_state, state_change)
    elif type(state_change) == ContractReceiveNewPaymentNetwork:
        assert isinstance(state_change, ContractReceiveNewPaymentNetwork), MYPY_ANNOTATION
        iteration = handle_new_payment_network(chain_state, state_change)
    elif type(state_change) == ContractReceiveNewTokenNetwork:
        assert isinstance(state_change, ContractReceiveNewTokenNetwork), MYPY_ANNOTATION
        iteration = handle_tokenadded(chain_state, state_change)
    elif type(state_change) == ContractReceiveChannelBatchUnlock:
        assert isinstance(state_change, ContractReceiveChannelBatchUnlock), MYPY_ANNOTATION
        iteration = handle_token_network_action(chain_state, state_change)
    elif type(state_change) == ContractReceiveChannelNew:
        assert isinstance(state_change, ContractReceiveChannelNew), MYPY_ANNOTATION
        iteration = handle_token_network_action(chain_state, state_change)
    elif type(state_change) == ContractReceiveChannelClosed:
        assert isinstance(state_change, ContractReceiveChannelClosed), MYPY_ANNOTATION
        iteration = handle_contract_receive_channel_closed(chain_state, state_change, chain_state.our_address)
    elif type(state_change) == ContractReceiveChannelClosedLight:
        assert isinstance(state_change, ContractReceiveChannelClosedLight), MYPY_ANNOTATION
        iteration = handle_contract_receive_channel_closed_light(chain_state, state_change)
    elif type(state_change) == ContractReceiveChannelNewBalance:
        assert isinstance(state_change, ContractReceiveChannelNewBalance), MYPY_ANNOTATION
        iteration = handle_token_network_action(chain_state, state_change)
    elif type(state_change) == ContractReceiveChannelSettled:
        assert isinstance(state_change, ContractReceiveChannelSettled), MYPY_ANNOTATION
        iteration = handle_token_network_action(chain_state, state_change)
    elif type(state_change) == ContractReceiveChannelSettledLight:
        assert isinstance(state_change, ContractReceiveChannelSettledLight), MYPY_ANNOTATION
        iteration = handle_token_network_action(chain_state, state_change)
    elif type(state_change) == ContractReceiveRouteNew:
        assert isinstance(state_change, ContractReceiveRouteNew), MYPY_ANNOTATION
        iteration = handle_token_network_action(chain_state, state_change)
    elif type(state_change) == ContractReceiveRouteClosed:
        assert isinstance(state_change, ContractReceiveRouteClosed), MYPY_ANNOTATION
        iteration = handle_token_network_action(chain_state, state_change)
    elif type(state_change) == ContractReceiveSecretReveal:
        assert isinstance(state_change, ContractReceiveSecretReveal), MYPY_ANNOTATION
        iteration = handle_contract_secret_reveal(chain_state, state_change)
    elif type(state_change) == ContractReceiveSecretRevealLight:
        assert isinstance(state_change, ContractReceiveSecretRevealLight), MYPY_ANNOTATION
        iteration = handle_contract_secret_reveal_light(chain_state, state_change)
    elif type(state_change) == ContractReceiveUpdateTransfer:
        assert isinstance(state_change, ContractReceiveUpdateTransfer), MYPY_ANNOTATION
        iteration = handle_token_network_action(chain_state, state_change)
    elif type(state_change) == ReceiveDelivered:
        assert isinstance(state_change, ReceiveDelivered), MYPY_ANNOTATION
        iteration = handle_delivered(chain_state, state_change)
    elif type(state_change) == ReceiveSecretReveal:
        assert isinstance(state_change, ReceiveSecretReveal), MYPY_ANNOTATION
        iteration = handle_secret_reveal(chain_state, state_change)
    elif type(state_change) == ActionTransferReroute:
        assert isinstance(state_change, ActionTransferReroute), MYPY_ANNOTATION
        iteration = handle_receive_transfer_refund_cancel_route(chain_state, state_change, storage)
    elif type(state_change) == ReceiveTransferRefund:
        assert isinstance(state_change, ReceiveTransferRefund), MYPY_ANNOTATION
        iteration = handle_receive_transfer_refund(chain_state, state_change)
    elif type(state_change) == ReceiveSecretRequest:
        assert isinstance(state_change, ReceiveSecretRequest), MYPY_ANNOTATION
        iteration = handle_receive_secret_request(chain_state, state_change)
    elif type(state_change) == ReceiveSecretRequestLight:
        assert isinstance(state_change, ReceiveSecretRequestLight), MYPY_ANNOTATION
        iteration = handle_receive_secret_request_light(chain_state, state_change)
    elif type(state_change) == ReceiveProcessed:
        assert isinstance(state_change, ReceiveProcessed), MYPY_ANNOTATION
        iteration = handle_processed(chain_state, state_change)
    elif type(state_change) == ReceiveUnlock:
        assert isinstance(state_change, ReceiveUnlock), MYPY_ANNOTATION
        iteration = handle_receive_unlock(chain_state, state_change)
    elif type(state_change) == ReceiveUnlockLight:
        assert isinstance(state_change, ReceiveUnlockLight), MYPY_ANNOTATION
        iteration = handle_receive_unlock_light(chain_state, state_change)
    elif type(state_change) == ReceiveLockExpired:
        assert isinstance(state_change, ReceiveLockExpired), MYPY_ANNOTATION
        iteration = handle_receive_lock_expired(chain_state, state_change)
    elif type(state_change) == ReceiveLockExpiredLight:
        assert isinstance(state_change, ReceiveLockExpiredLight), MYPY_ANNOTATION
        iteration = handle_receive_lock_expired_light(chain_state, state_change, storage)
    elif type(state_change) == ActionInitInitiatorLight:
        iteration = handle_init_initiator_light(chain_state, state_change)
    elif type(state_change) == ActionSendSecretRevealLight:
        iteration = handle_init_reveal_secret_light(chain_state, state_change)
    elif type(state_change) == ActionSendSecretRequestLight:
        iteration = handle_init_secret_request_light(chain_state, state_change)
    elif type(state_change) == ReceiveSecretRevealLight:
        assert isinstance(state_change, ReceiveSecretRevealLight), MYPY_ANNOTATION
        iteration = handle_secret_reveal_light(chain_state, state_change)
    elif type(state_change) == ActionSendUnlockLight:
        assert isinstance(state_change, ActionSendUnlockLight), MYPY_ANNOTATION
        iteration = handle_init_unlock_light(chain_state, state_change)
    elif type(state_change) == ActionSendLockExpiredLight:
        assert isinstance(state_change, ActionSendLockExpiredLight), MYPY_ANNOTATION
        iteration = handle_init_send_lock_expired_light(chain_state, state_change)
    elif type(state_change) == StoreRefundTransferLight:
        assert isinstance(state_change, StoreRefundTransferLight), MYPY_ANNOTATION
        iteration = handle_store_refund_transfer_light(chain_state, state_change)
    assert chain_state is not None, "chain_state must be set"
    return iteration


def is_transaction_effect_satisfied(
    chain_state: ChainState, transaction: ContractSendEvent, state_change: StateChange
) -> bool:
    """ True if the side-effect of `transaction` is satisfied by
    `state_change`.

    This predicate is used to clear the transaction queue. This should only be
    done once the expected side effect of a transaction is achieved. This
    doesn't necessarily mean that the transaction sent by *this* node was
    mined, but only that *some* transaction which achieves the same side-effect
    was successfully executed and mined. This distinction is important for
    restarts and to reduce the number of state changes.

    On restarts: The state of the on-chain channel could have changed while the
    node was offline. Once the node learns about the change (e.g. the channel
    was settled), new transactions can be dispatched by Raiden as a side effect for the
    on-chain *event* (e.g. do the batch unlock with the latest merkle tree),
    but the dispatched transaction could have been completed by another agent (e.g.
    the partner node). For these cases, the transaction from a different
    address which achieves the same side-effect is sufficient, otherwise
    unnecessary transactions would be sent by the node.

    NOTE: The above is not important for transactions sent as a side-effect for
    a new *block*. On restart the node first synchronizes its state by querying
    for new events, only after the off-chain state is up-to-date, a Block state
    change is dispatched. At this point some transactions are not required
    anymore and therefore are not dispatched.

    On the number of state changes: Accepting a transaction from another
    address removes the need for clearing state changes, e.g. when our
    node's close transaction fails but its partner's close transaction
    succeeds.
    """
    # These transactions are not made atomic through the WAL. They are sent
    # exclusively through the external APIs.
    #
    #  - ContractReceiveChannelNew
    #  - ContractReceiveChannelNewBalance
    #  - ContractReceiveNewPaymentNetwork
    #  - ContractReceiveNewTokenNetwork
    #  - ContractReceiveRouteNew
    #
    # Note: Deposits and Withdraws must consider a transaction with a higher
    # value as sufficient, because the values are monotonically increasing and
    # the transaction with a lower value will never be executed.

    # Transactions are used to change the on-chain state of a channel. It
    # doesn't matter if the sender of the transaction is the local node or
    # another node authorized to perform the operation. So, for the following
    # transactions, as long as the side-effects are the same, the local
    # transaction can be removed from the queue.
    #
    # - An update transfer can be done by a trusted third party (i.e. monitoring service)
    # - A close transaction can be sent by our partner
    # - A settle transaction can be sent by anyone
    # - A secret reveal can be done by anyone

    # - A lower nonce is not a valid replacement, since that is an older balance
    #   proof
    # - A larger raiden state change nonce is impossible.
    #   That would require the partner node to produce an invalid balance proof,
    #   and this node to accept the invalid balance proof and sign it
    is_valid_update_transfer = (
        isinstance(state_change, ContractReceiveUpdateTransfer)
        and isinstance(transaction, ContractSendChannelUpdateTransfer)
        and state_change.token_network_identifier == transaction.token_network_identifier
        and state_change.channel_identifier == transaction.channel_identifier
        and state_change.nonce == transaction.balance_proof.nonce
    )
    if is_valid_update_transfer:
        return True

    # The balance proof data cannot be verified, the local close could have
    # lost a race against a remote close, and the balance proof data would be
    # the one provided by this node's partner
    is_valid_close = (
        (isinstance(state_change, ContractReceiveChannelClosed) or
         (isinstance(state_change, ContractReceiveChannelClosedLight)))
        and isinstance(transaction, ContractSendChannelClose)
        and state_change.token_network_identifier == transaction.token_network_identifier
        and state_change.channel_identifier == transaction.channel_identifier
    )

    if is_valid_close:
        return True

    is_valid_settle = (
        isinstance(state_change, ContractReceiveChannelSettled)
        and isinstance(transaction, ContractSendChannelSettle)
        and state_change.token_network_identifier == transaction.token_network_identifier
        and state_change.channel_identifier == transaction.channel_identifier
    )

    if is_valid_settle:
        return True

    is_valid_secret_reveal = (
        isinstance(state_change, ContractReceiveSecretReveal)
        and isinstance(transaction, ContractSendSecretReveal)
        and state_change.secret == transaction.secret
    )
    if is_valid_secret_reveal:
        return True

    is_batch_unlock = isinstance(state_change, ContractReceiveChannelBatchUnlock) and isinstance(
        transaction, ContractSendChannelBatchUnlock
    )
    if is_batch_unlock:
        assert isinstance(state_change, ContractReceiveChannelBatchUnlock), MYPY_ANNOTATION
        assert isinstance(transaction, ContractSendChannelBatchUnlock), MYPY_ANNOTATION

        our_address = chain_state.our_address

        # Don't assume that because we sent the transaction, we are a
        # participant
        partner_address = None
        if state_change.participant == our_address:
            partner_address = state_change.partner
        elif state_change.partner == our_address:
            partner_address = state_change.participant

        # Use the second address as the partner address, but check that a
        # channel exists for our_address and partner_address
        if partner_address:
            channel_state = views.get_channelstate_by_token_network_and_partner(
                chain_state, TokenNetworkID(state_change.token_network_identifier), our_address, partner_address
            )
            # If the channel was cleared, that means that both
            # sides of the channel were successfully unlocked.
            # In this case, we clear the batch unlock
            # transaction from the queue only in case there
            # were no more locked funds to unlock.
            if channel_state is None:
                return True

    return False


def is_transaction_invalidated(transaction: ContractSendEvent, state_change: StateChange) -> bool:
    """ True if the `transaction` is made invalid by `state_change`.

    Some transactions will fail due to race conditions. The races are:

    - Another transaction which has the same side effect is executed before.
    - Another transaction which *invalidates* the state of the smart contract
    required by the local transaction is executed before it.

    The first case is handled by the predicate `is_transaction_effect_satisfied`,
    where a transaction from a different source which does the same thing is
    considered. This predicate handles the second scenario.

    A transaction can **only** invalidate another iff both share a valid
    initial state but a different end state.

    Valid example:

        A close can invalidate a deposit, because both a close and a deposit
        can be executed from an opened state (same initial state), but a close
        transaction will transition the channel to a closed state which doesn't
        allow for deposits (different end state).

    Invalid example:

        A settle transaction cannot invalidate a deposit because a settle is
        only allowed for the closed state and deposits are only allowed for
        the open state. In such a case a deposit should never have been sent.
        The deposit transaction for an invalid state is a bug and not a
        transaction which was invalidated.
    """
    # Most transactions cannot be invalidated by others. These are:
    #
    # - close transactions
    # - settle transactions
    # - batch unlocks
    #
    # Deposits and withdraws are invalidated by the close, but these are not
    # made atomic through the WAL.

    is_our_failed_update_transfer = (
        isinstance(state_change, ContractReceiveChannelSettled)
        and isinstance(transaction, ContractSendChannelUpdateTransfer)
        and state_change.token_network_identifier == transaction.token_network_identifier
        and state_change.channel_identifier == transaction.channel_identifier
    )
    if is_our_failed_update_transfer:
        return True

    return False


def is_transaction_expired(transaction: ContractSendEvent, block_number: BlockNumber) -> bool:
    """ True if transaction cannot be mined because it has expired.

    Some transactions are time dependent, e.g. the secret registration must be
    done before the lock expiration, and the update transfer must be done
    before the settlement window is over. If the current block is higher than
    any of these expirations blocks, the transaction is expired and cannot be
    successfully executed.
    """

    is_update_expired = (
        isinstance(transaction, ContractSendChannelUpdateTransfer)
        and transaction.expiration < block_number
    )
    if is_update_expired:
        return True

    is_secret_register_expired = (
        isinstance(transaction, ContractSendSecretReveal) and transaction.expiration < block_number
    )
    if is_secret_register_expired:
        return True

    return False


def is_transaction_pending(
    chain_state: ChainState, transaction: ContractSendEvent, state_change: StateChange
) -> bool:
    return not (
        is_transaction_effect_satisfied(chain_state, transaction, state_change)
        or is_transaction_invalidated(transaction, state_change)
        or is_transaction_expired(transaction, chain_state.block_number)
    )


def update_queues(iteration: TransitionResult[ChainState], state_change: StateChange) -> None:
    chain_state = iteration.new_state
    assert chain_state is not None, "chain_state must be set"

    if isinstance(state_change, ContractReceiveStateChange):
        pending_transactions = [
            transaction
            for transaction in chain_state.pending_transactions
            if is_transaction_pending(chain_state, transaction, state_change)
        ]
        chain_state.pending_transactions = pending_transactions

    for event in iteration.events:
        if isinstance(event, SendMessageEvent):
            queue = chain_state.queueids_to_queues.setdefault(event.queue_identifier, [])
            queue.append(event)

        if isinstance(event, ContractSendEvent):
            if is_transaction_pending(chain_state, event, state_change):
                chain_state.pending_transactions.append(event)


def state_transition(
    chain_state: ChainState, state_change: StateChange, storage
) -> TransitionResult[ChainState]:
    # pylint: disable=too-many-branches,unidiomatic-typecheck

    iteration = handle_state_change(chain_state, state_change, storage)

    update_queues(iteration, state_change)
    sanity_check(iteration)

    return iteration


def _get_channels_close_events(
    chain_state: ChainState, token_network_state: TokenNetworkState
) -> List[Event]:
    events = []
    for channel_identifiers in token_network_state.partneraddresses_to_channelidentifiers.values():
        channel_states = [
            token_network_state.channelidentifiers_to_channels[channel_id]
            for channel_id in channel_identifiers
        ]
        filtered_channel_states = views.filter_channels_by_status(
            channel_states, [channel.CHANNEL_STATE_UNUSABLE]
        )
        for channel_state in filtered_channel_states:
            events.extend(
                channel.events_for_close(
                    channel_state=channel_state,
                    block_number=chain_state.block_number,
                    block_hash=chain_state.block_hash
                )
            )
    return events
