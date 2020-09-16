from typing import Optional

from eth_utils import to_checksum_address, to_hex

from raiden.constants import EMPTY_HASH
from raiden.exceptions import RaidenUnrecoverableError
from raiden.storage.restore import channel_state_until_state_change
from raiden.transfer.channel import get_batch_unlock_gain
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.state import ChainState, NettingChannelState, NettingChannelEndState
from raiden.transfer.utils import get_state_change_with_balance_proof_by_locksroot, \
    get_event_with_balance_proof_by_locksroot
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

    canonical_identifier = canonical_identifier
    token_network_identifier = canonical_identifier.token_network_address
    participant = participant

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
    our_locksroot = channel_state.our_state.onchain_locksroot
    # we want to unlock because there are on-chain unlocked locks
    return our_locksroot != EMPTY_HASH


def should_search_state_changes(
    channel_state: NettingChannelState,
) -> bool:
    partner_locksroot = channel_state.partner_state.onchain_locksroot
    # we want to unlock, because there are unlocked/unclaimed locks
    return partner_locksroot != EMPTY_HASH


def get_partner_state_for_unlock(
    raiden: "RaidenService",
    canonical_identifier: CanonicalIdentifier,
    participant: Address,
    channel_state: NettingChannelState
) -> Optional[NettingChannelEndState]:
    if should_search_state_changes(channel_state):
        state_change_record = get_state_change_with_balance_proof_by_locksroot(
            storage=raiden.wal.storage,
            canonical_identifier=canonical_identifier,
            locksroot=channel_state.partner_state.onchain_locksroot,
            sender=channel_state.partner_state.address,
        )
        state_change_identifier = state_change_record.state_change_identifier

        if not state_change_identifier:
            raise RaidenUnrecoverableError(
                f"Failed to find state that matches the current channel locksroots. "
                f"chain_id:{raiden.chain.network_id} "
                f"token_network:{to_checksum_address(canonical_identifier.token_network_address)} "
                f"channel:{canonical_identifier.channel_identifier} "
                f"participant:{to_checksum_address(participant)} "
                f"our_locksroot:{to_hex(channel_state.partner_state.onchain_locksroot)} "
                f"partner_locksroot:{to_hex(channel_state.partner_state.onchain_locksroot)} "
            )

        restored_channel_state = channel_state_until_state_change(
            raiden=raiden,
            canonical_identifier=canonical_identifier,
            state_change_identifier=state_change_identifier,
        )
        assert restored_channel_state is not None

        gain = get_batch_unlock_gain(restored_channel_state)

        if restored_channel_state.partner_state.address != participant or gain.from_partner_locks != 0:
            return restored_channel_state.partner_state
    return None


def get_our_state_for_unlock(
    raiden: "RaidenService",
    canonical_identifier: CanonicalIdentifier,
    participant: Address,
    channel_state: NettingChannelState
) -> Optional[NettingChannelEndState]:
    if should_search_events(channel_state):

        event_record = get_event_with_balance_proof_by_locksroot(
            storage=raiden.wal.storage,
            canonical_identifier=canonical_identifier,
            locksroot=channel_state.our_state.onchain_locksroot,
            recipient=channel_state.partner_state.address,
        )
        state_change_identifier = event_record.state_change_identifier

        if not state_change_identifier:
            raise RaidenUnrecoverableError(
                f"Failed to find event that match current channel locksroots. "
                f"chain_id:{raiden.chain.network_id} "
                f"token_network:{to_checksum_address(canonical_identifier.token_network_identifier)} "
                f"channel:{canonical_identifier.channel_identifier} "
                f"participant:{to_checksum_address(participant)} "
                f"our_locksroot:{to_hex(channel_state.our_state.onchain_locksroot)} "
                f"partner_locksroot:{to_hex(channel_state.partner_state.onchain_locksroot)} "
            )

        restored_channel_state = channel_state_until_state_change(
            raiden=raiden,
            canonical_identifier=canonical_identifier,
            state_change_identifier=state_change_identifier,
        )
        assert restored_channel_state is not None

        gain = get_batch_unlock_gain(restored_channel_state)

        if restored_channel_state.our_state.address != participant or gain.from_our_locks != 0:
            return restored_channel_state.our_state
    return None
