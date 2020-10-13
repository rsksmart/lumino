from eth_utils import to_checksum_address

from raiden.constants import EMPTY_HASH
from raiden.exceptions import RaidenUnrecoverableError
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.state import ChainState, NettingChannelState
from raiden.transfer.views import get_channelstate_by_token_network_and_partner
from raiden.utils import Address
from raiden.utils.typing import TokenNetworkID


def get_channel_state(
    raiden: "RaidenService",
    chain_state: ChainState,
    canonical_identifier: CanonicalIdentifier,
    participant: Address,
    our_address: Address
) -> NettingChannelState:

    token_network_identifier = canonical_identifier.token_network_address

    assert raiden.wal, "The Raiden Service must be initialized to handle events"

    channel_state = get_channelstate_by_token_network_and_partner(
        chain_state=chain_state,
        token_network_id=TokenNetworkID(token_network_identifier),
        creator_address=our_address,
        partner_address=participant,
    )

    if not channel_state:
        # channel was cleaned up already due to an unlock
        raise RaidenUnrecoverableError(
            f"Failed to find channel state with partner:"
            f"{to_checksum_address(participant)}, token_network:pex(token_network_identifier)"
        )
    return channel_state


def should_search_events(
    channel_state: NettingChannelState,
) -> bool:
    # we want to unlock because there are on-chain unlocked locks
    return channel_state.our_state.onchain_locksroot != EMPTY_HASH


def should_search_state_changes(
    channel_state: NettingChannelState,
) -> bool:
    # we want to unlock, because there are unlocked/unclaimed locks
    return channel_state.partner_state.onchain_locksroot != EMPTY_HASH
