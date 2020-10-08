import random

from raiden.transfer.architecture import Event
from raiden.transfer.channel import get_status
from raiden.transfer.events import ContractSendSecretReveal, ContractSendSecretRevealLight
from raiden.transfer.mediated_transfer.state import TargetTransferState
from raiden.transfer.state import (
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATES_PRIOR_TO_CLOSED,
    NettingChannelState,
    message_identifier_from_prng,
)
from raiden.utils.typing import BlockExpiration, BlockHash, List, Secret, T_Secret


def events_for_onchain_secretreveal(
    channel_state: NettingChannelState,
    secret: Secret,
    expiration: BlockExpiration,
    block_hash: BlockHash,
    target_state: TargetTransferState = None,
    pseudo_random_generator: random.Random = None
) -> List[Event]:
    if not isinstance(secret, T_Secret):
        raise ValueError("secret must be a Secret instance")

    if get_status(channel_state) in CHANNEL_STATES_PRIOR_TO_CLOSED + (CHANNEL_STATE_CLOSED,):
        if not channel_state.is_light_channel:
            return [
                ContractSendSecretReveal(
                    expiration=expiration,
                    secret=secret,
                    triggered_by_block_hash=block_hash,
                )
            ]
        if target_state:
            return [
                ContractSendSecretRevealLight(
                    message_id=message_identifier_from_prng(pseudo_random_generator),
                    payment_identifier=target_state.transfer.payment_identifier,
                    light_client_address=channel_state.our_state.address
                )
            ]

    return []
