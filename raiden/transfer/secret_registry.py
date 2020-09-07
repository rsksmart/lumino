from typing import Optional

from raiden.lightclient.handlers.light_client_service import LightClientService
from raiden.lightclient.models.light_client_protocol_message import LightClientProtocolMessageType
from raiden.messages import RequestRegisterSecret
from raiden.transfer.architecture import Event
from raiden.transfer.channel import get_status
from raiden.transfer.events import ContractSendSecretReveal
from raiden.transfer.mediated_transfer.events import StoreMessageEvent
from raiden.transfer.mediated_transfer.state import TargetTransferState
from raiden.transfer.state import (
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATES_PRIOR_TO_CLOSED,
    NettingChannelState,
)
from raiden.utils.typing import BlockExpiration, BlockHash, List, Secret, T_Secret, MessageID


def events_for_onchain_secretreveal(
    channel_state: NettingChannelState,
    secret: Secret,
    expiration: BlockExpiration,
    block_hash: BlockHash,
    target_state: Optional[TargetTransferState]
) -> List[Event]:
    events: List[Event] = list()

    if not isinstance(secret, T_Secret):
        raise ValueError("secret must be a Secret instance")

    if get_status(channel_state) in CHANNEL_STATES_PRIOR_TO_CLOSED + (CHANNEL_STATE_CLOSED,):
        if not channel_state.is_light_channel:
            return [
                ContractSendSecretReveal(
                    expiration=expiration,
                    secret=secret,
                    triggered_by_block_hash=block_hash,
                    our_address=channel_state.our_state.address
                )
            ]
        elif target_state is not None:
            return [
                StoreMessageEvent(
                    message_id=target_state.transfer.message_identifier,
                    payment_id=target_state.transfer.payment_identifier,
                    message_order=0,
                    message=RequestRegisterSecret(),
                    is_signed=False,
                    message_type=LightClientProtocolMessageType.RequestRegisterSecret
                )
            ]

    return []
