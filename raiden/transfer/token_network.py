import copy

from eth_utils import decode_hex
from raiden.transfer import channel, views
from raiden.transfer.architecture import Event, StateChange, TransitionResult
from raiden.transfer.state import TokenNetworkState, NettingChannelState
from raiden.transfer.state_change import (
    ActionChannelClose,
    ActionChannelSetFee,
    ContractReceiveChannelBatchUnlock,
    ContractReceiveChannelClosed,
    ContractReceiveChannelNew,
    ContractReceiveChannelNewBalance,
    ContractReceiveChannelSettled,
    ContractReceiveRouteClosed,
    ContractReceiveRouteNew,
    ContractReceiveUpdateTransfer,
    ContractReceiveChannelClosedLight, ContractReceiveChannelSettledLight)
from raiden.utils.typing import MYPY_ANNOTATION, BlockHash, BlockNumber, List, Union, Dict, AddressHex

# TODO: The proper solution would be to introduce a marker for state changes
# that contains channel IDs and other specific channel attributes
StateChangeWithChannelID = Union[
    ActionChannelClose,
    ActionChannelSetFee,
    ContractReceiveChannelClosed,
    ContractReceiveChannelNewBalance,
    ContractReceiveChannelSettled,
    ContractReceiveUpdateTransfer,
]


def subdispatch_to_channels_by_participant_address(
    token_network_state: TokenNetworkState,
    state_change: StateChangeWithChannelID,
    block_number: BlockNumber,
    block_hash: BlockHash,
    participant_address: AddressHex = None
) -> TransitionResult:
    if not participant_address:
        return TransitionResult(token_network_state, [])
    channel_states = get_channels_to_dispatch_statechange(
        participant_address, state_change, token_network_state
    )
    return subdispatch_to_channels(block_hash, block_number, channel_states, state_change, token_network_state)


def subdispatch_to_channels(
    block_hash: BlockHash,
    block_number: BlockNumber,
    channel_states: List[NettingChannelState],
    state_change: StateChangeWithChannelID,
    token_network_state: TokenNetworkState
) -> TransitionResult:
    events = []
    ids_to_channels = token_network_state.channelidentifiers_to_channels
    for channel_state in channel_states:
        channel_result = channel.state_transition(
            channel_state=channel_state,
            state_change=state_change,
            block_number=block_number,
            block_hash=block_hash,
        )

        partner_to_channelids = token_network_state.partneraddresses_to_channelidentifiers[
            channel_state.partner_state.address
        ]

        channel_identifier = state_change.channel_identifier
        if channel_result.new_state is None:
            del ids_to_channels[channel_state.our_state.address][channel_identifier]
            partner_to_channelids.remove(channel_identifier)
        else:
            ids_to_channels[channel_state.our_state.address][channel_identifier] = channel_result.new_state

        events.extend(channel_result.events)
    return TransitionResult(token_network_state, events)


def get_channels_to_dispatch_statechange(
    participant_address: AddressHex,
    state_change: StateChangeWithChannelID,
    token_network_state: TokenNetworkState
) -> List[NettingChannelState]:
    """
    Retrieve which channels the state_change should be dispatched to.
    In most situations, the state_change should be dispatched to this node's side of the channel.
    If this node runs in hub mode, and both sides of the channel are light client handled by this hub,
    then it's needed to dispatch the state_change to both channel_states (one per light client)
    :param participant_address: address of the participant that fired the state_change
    :param state_change: state_change to dispatch
    :param token_network_state: token network where to look for channels
    :return: Channel where the state_change should be dispatched
    """
    channel_states = []
    ids_to_channels = token_network_state.channelidentifiers_to_channels
    # is a handled lc or is the node itself?
    participant_is_ours = participant_address in ids_to_channels
    if participant_is_ours:
        channel_state = ids_to_channels[participant_address].get(state_change.channel_identifier)
        channel_states.append(channel_state)
        if channel_state.both_participants_are_light_clients:
            partner_channel = ids_to_channels[channel_state.partner_state.address]
            partner_channel_state = partner_channel.get(channel_state.identifier)
            channel_states.append(partner_channel_state)
    else:
        lc_address = views.get_lc_address_by_channel_id_and_partner(token_network_state, participant_address,
                                                                    state_change.canonical_identifier)
        lc_is_ours = lc_address in ids_to_channels
        if lc_is_ours:
            lc_channel_state = ids_to_channels[lc_address].get(state_change.channel_identifier)
            channel_states.append(lc_channel_state)

    return channel_states


def handle_channel_close(
    token_network_state: TokenNetworkState,
    state_change: ActionChannelClose,
    block_number: BlockNumber,
    block_hash: BlockHash,
) -> TransitionResult:
    return subdispatch_to_channels_by_participant_address(
        token_network_state=token_network_state,
        state_change=state_change,
        block_number=block_number,
        block_hash=block_hash,
        participant_address=state_change.participant1
    )


def handle_channelnew(
    token_network_state: TokenNetworkState, state_change: ContractReceiveChannelNew
) -> TransitionResult:
    events: List[Event] = list()

    channel_state = state_change.channel_state
    channel_identifier = channel_state.identifier
    our_address = channel_state.our_state.address
    partner_address = channel_state.partner_state.address

    token_network_state.network_graph.network.add_edge(our_address, partner_address)
    token_network_state.network_graph.channel_identifier_to_participants[
        state_change.channel_identifier
    ] = (our_address, partner_address)

    if our_address not in token_network_state.channelidentifiers_to_channels:
        token_network_state.channelidentifiers_to_channels[our_address] = dict()

    # Ignore duplicated channelnew events. For this to work properly on channel
    # reopens the blockchain events ChannelSettled and ChannelOpened must be
    # processed in correct order, this should be guaranteed by the filters in
    # the ethereum node
    if channel_identifier not in token_network_state.channelidentifiers_to_channels[our_address]:

        token_network_state.channelidentifiers_to_channels[our_address][channel_identifier] = channel_state


        if channel_state.both_participants_are_light_clients:
            ## 2 light clients using the same Hub
            if partner_address not in token_network_state.channelidentifiers_to_channels:
                token_network_state.channelidentifiers_to_channels[partner_address] = dict()
            channel_state_copy = copy.deepcopy(channel_state)
            channel_state_copy.our_state, channel_state_copy.partner_state = channel_state_copy.partner_state, channel_state_copy.our_state
            token_network_state.channelidentifiers_to_channels[partner_address][channel_identifier] = channel_state_copy


        addresses_to_ids = token_network_state.partneraddresses_to_channelidentifiers
        addresses_to_ids[our_address].append(channel_identifier)
        addresses_to_ids[partner_address].append(channel_identifier)

    return TransitionResult(token_network_state, events)


def handle_balance(
    token_network_state: TokenNetworkState,
    state_change: ContractReceiveChannelNewBalance,
    block_number: BlockNumber,
    block_hash: BlockHash,
    participant: AddressHex
) -> TransitionResult:
    return subdispatch_to_channels_by_participant_address(
        token_network_state=token_network_state,
        state_change=state_change,
        block_number=block_number,
        block_hash=block_hash,
        participant_address=participant
    )


def handle_closed(
    token_network_state: TokenNetworkState,
    state_change: Union[ContractReceiveChannelClosed, ContractReceiveChannelClosedLight],
    block_number: BlockNumber,
    block_hash: BlockHash,
) -> TransitionResult:
    network_graph_state = token_network_state.network_graph
    node_address = None
    # it might happen that both partners close at the same time, so the channel might
    # already be deleted
    if state_change.channel_identifier in network_graph_state.channel_identifier_to_participants:
        participant1, participant2 = network_graph_state.channel_identifier_to_participants[
            state_change.channel_identifier
        ]

        if participant1 is not None and participant2 is not None:
            token_network_state.network_graph.network.remove_edge(participant1, participant2)
            del token_network_state.network_graph.channel_identifier_to_participants[
                state_change.channel_identifier
            ]
            node_address = participant1

    return subdispatch_to_channels_by_participant_address(
        token_network_state=token_network_state,
        state_change=state_change,
        block_number=block_number,
        block_hash=block_hash,
        participant_address=node_address
    )


def handle_settled(
    token_network_state: TokenNetworkState,
    state_change: ContractReceiveChannelSettled,
    block_number: BlockNumber,
    block_hash: BlockHash,
) -> TransitionResult:
    return subdispatch_to_channels_by_participant_address(
        token_network_state=token_network_state,
        state_change=state_change,
        block_number=block_number,
        block_hash=block_hash,
        participant_address=state_change.participant1
    )


def handle_updated_transfer(
    token_network_state: TokenNetworkState,
    state_change: ContractReceiveUpdateTransfer,
    block_number: BlockNumber,
    block_hash: BlockHash,
) -> TransitionResult:
    return subdispatch_to_channels_by_participant_address(
        token_network_state=token_network_state,
        state_change=state_change,
        block_number=block_number,
        block_hash=block_hash,
    )


def handle_batch_unlock(
    token_network_state: TokenNetworkState,
    state_change: ContractReceiveChannelBatchUnlock,
    block_number: BlockNumber,
    block_hash: BlockHash,
) -> TransitionResult:
    events = list()
    channel_state = None
    if token_network_state.channelidentifiers_to_channels.get(state_change.participant) is not None:
        channel_state = token_network_state.channelidentifiers_to_channels[state_change.participant].get(
            state_change.canonical_identifier.channel_identifier
        )
    if channel_state is not None:
        sub_iteration = channel.state_transition(
            channel_state=channel_state,
            state_change=state_change,
            block_number=block_number,
            block_hash=block_hash,
        )
        events.extend(sub_iteration.events)

        if sub_iteration.new_state is None:

            token_network_state.partneraddresses_to_channelidentifiers[
                channel_state.partner_state.address
            ].remove(channel_state.identifier)

            del token_network_state.channelidentifiers_to_channels[state_change.participant][channel_state.identifier]

    return TransitionResult(token_network_state, events)


def handle_newroute(
    token_network_state: TokenNetworkState, state_change: ContractReceiveRouteNew
) -> TransitionResult:
    events: List[Event] = list()

    token_network_state.network_graph.network.add_edge(
        state_change.participant1, state_change.participant2
    )
    token_network_state.network_graph.channel_identifier_to_participants[
        state_change.channel_identifier
    ] = (state_change.participant1, state_change.participant2)

    return TransitionResult(token_network_state, events)


def handle_closeroute(
    token_network_state: TokenNetworkState, state_change: ContractReceiveRouteClosed
) -> TransitionResult:
    events: List[Event] = list()

    network_graph_state = token_network_state.network_graph

    # it might happen that both partners close at the same time, so the channel might
    # already be deleted
    if state_change.channel_identifier in network_graph_state.channel_identifier_to_participants:
        participant1, participant2 = network_graph_state.channel_identifier_to_participants[
            state_change.channel_identifier
        ]
        token_network_state.network_graph.network.remove_edge(participant1, participant2)
        del token_network_state.network_graph.channel_identifier_to_participants[
            state_change.channel_identifier
        ]

    return TransitionResult(token_network_state, events)


def state_transition(
    token_network_state: TokenNetworkState,
    state_change: StateChange,
    block_number: BlockNumber,
    block_hash: BlockHash,
) -> TransitionResult:
    # pylint: disable=too-many-branches,unidiomatic-typecheck

    if type(state_change) == ActionChannelClose:
        assert isinstance(state_change, ActionChannelClose), MYPY_ANNOTATION
        iteration = handle_channel_close(
            token_network_state, state_change, block_number, block_hash
        )
    elif type(state_change) == ActionChannelSetFee:
        assert isinstance(state_change, ActionChannelSetFee), MYPY_ANNOTATION
        iteration = subdispatch_to_channel_by_id(
            token_network_state=token_network_state,
            state_change=state_change,
            block_number=block_number,
            block_hash=block_hash,
        )
    elif type(state_change) == ContractReceiveChannelNew:
        assert isinstance(state_change, ContractReceiveChannelNew), MYPY_ANNOTATION
        iteration = handle_channelnew(token_network_state, state_change)
    elif type(state_change) == ContractReceiveChannelNewBalance:
        assert isinstance(state_change, ContractReceiveChannelNewBalance), MYPY_ANNOTATION
        client_address = state_change.participant
        if type(client_address) != bytes:
            client_address = decode_hex(state_change.participant)
        iteration = handle_balance(token_network_state, state_change, block_number, block_hash, client_address)
    elif type(state_change) == ContractReceiveChannelClosed:
        assert isinstance(state_change, ContractReceiveChannelClosed), MYPY_ANNOTATION
        iteration = handle_closed(token_network_state, state_change, block_number, block_hash)
    elif type(state_change) == ContractReceiveChannelClosedLight:
        assert isinstance(state_change, ContractReceiveChannelClosedLight), MYPY_ANNOTATION
        iteration = handle_closed(token_network_state, state_change, block_number, block_hash)
    elif type(state_change) == ContractReceiveChannelSettled:
        assert isinstance(state_change, ContractReceiveChannelSettled), MYPY_ANNOTATION
        iteration = handle_settled(token_network_state, state_change, block_number, block_hash)
    elif type(state_change) == ContractReceiveChannelSettledLight:
        assert isinstance(state_change, ContractReceiveChannelSettledLight), MYPY_ANNOTATION
        iteration = handle_settled(token_network_state, state_change, block_number, block_hash)
    elif type(state_change) == ContractReceiveUpdateTransfer:
        assert isinstance(state_change, ContractReceiveUpdateTransfer), MYPY_ANNOTATION
        iteration = handle_updated_transfer(token_network_state, state_change, block_number, block_hash)
    elif type(state_change) == ContractReceiveChannelBatchUnlock:
        assert isinstance(state_change, ContractReceiveChannelBatchUnlock), MYPY_ANNOTATION
        iteration = handle_batch_unlock(
            token_network_state, state_change, block_number, block_hash
        )
    elif type(state_change) == ContractReceiveRouteNew:
        assert isinstance(state_change, ContractReceiveRouteNew), MYPY_ANNOTATION
        iteration = handle_newroute(token_network_state, state_change)
    elif type(state_change) == ContractReceiveRouteClosed:
        assert isinstance(state_change, ContractReceiveRouteClosed), MYPY_ANNOTATION
        iteration = handle_closeroute(token_network_state, state_change)

    return iteration
