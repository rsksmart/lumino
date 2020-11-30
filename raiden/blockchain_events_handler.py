from typing import TYPE_CHECKING, Optional

import gevent
import structlog
from eth_typing import ChecksumAddress
from eth_utils import to_checksum_address, encode_hex
from raiden_contracts.constants import (
    EVENT_SECRET_REVEALED,
    EVENT_TOKEN_NETWORK_CREATED,
    ChannelEvent,
)

from raiden.blockchain.events import Event
from raiden.blockchain.state import get_channel_state
from raiden.connection_manager import ConnectionManager
from raiden.exceptions import AddressWithoutCode
from raiden.lightclient.handlers.light_client_message_handler import LightClientMessageHandler
from raiden.lightclient.handlers.light_client_service import LightClientService
from raiden.network.proxies.utils import get_onchain_locksroots
from raiden.transfer import views
from raiden.transfer.architecture import StateChange
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.state import TokenNetworkState, TransactionChannelNewBalance, ChainState, NettingChannelState
from raiden.transfer.state_change import (
    ContractReceiveChannelBatchUnlock,
    ContractReceiveChannelClosed,
    ContractReceiveChannelNew,
    ContractReceiveChannelNewBalance,
    ContractReceiveChannelSettled,
    ContractReceiveNewTokenNetwork,
    ContractReceiveRouteClosed,
    ContractReceiveRouteNew,
    ContractReceiveSecretReveal,
    ContractReceiveUpdateTransfer,
    ContractReceiveChannelClosedLight,
    ContractReceiveChannelSettledLight, ContractReceiveSecretRevealLight
)
from raiden.transfer.utils import (
    get_event_with_balance_proof_by_locksroot,
    get_state_change_with_balance_proof_by_locksroot,
)
from raiden.transfer.views import get_token_network_by_identifier
from raiden.utils import pex, typing
from raiden.utils.typing import TokenNetworkID, AddressHex

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.raiden_service import RaidenService  # noqa: F401

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


def handle_tokennetwork_new(raiden: "RaidenService", event: Event):
    """ Handles a `TokenNetworkCreated` event. """
    data = event.event_data
    args = data["args"]
    block_number = data["block_number"]
    token_network_address = args["token_network_address"]
    token_address = typing.TokenAddress(args["token_address"])
    block_hash = data["block_hash"]
    try:
        token_network_proxy = raiden.chain.token_network(token_network_address)
        raiden.blockchain_events.add_token_network_listener(
            token_network_proxy=token_network_proxy,
            contract_manager=raiden.contract_manager,
            from_block=block_number,
        )

        token_network_state = TokenNetworkState(token_network_address, token_address)

        transaction_hash = event.event_data["transaction_hash"]

        new_token_network = ContractReceiveNewTokenNetwork(
            transaction_hash=transaction_hash,
            payment_network_identifier=event.originating_contract,
            token_network=token_network_state,
            block_number=block_number,
            block_hash=block_hash,
        )
        raiden.handle_and_track_state_change(new_token_network)
    except AddressWithoutCode:
        log.info("TokenAddress without code, Address: %s", to_checksum_address(token_address))


def handle_channel_new(raiden: "RaidenService", event: Event):
    data = event.event_data
    block_number = data["block_number"]
    block_hash = data["block_hash"]
    args = data["args"]
    token_network_identifier = event.originating_contract
    transaction_hash = event.event_data["transaction_hash"]
    channel_identifier = args["channel_identifier"]
    participant1 = args["participant1"]
    participant2 = args["participant2"]


    # Check if at least one of the implied participants is a LC handled by the node
    is_participant1_handled_lc = LightClientService.is_handled_lc(
        client_address=to_checksum_address(encode_hex(participant1)),
        wal=raiden.wal
    )
    is_participant2_handled_lc = LightClientService.is_handled_lc(
        client_address=to_checksum_address(encode_hex(participant2)),
        wal=raiden.wal
    )
    is_light_channel = is_participant1_handled_lc or is_participant2_handled_lc
    if is_light_channel:
        if is_participant1_handled_lc:
            create_channel(
                block_hash=block_hash,
                block_number=block_number,
                channel_identifier=channel_identifier,
                participant1=participant1,
                participant2=participant2,
                token_network_identifier=token_network_identifier,
                transaction_hash=transaction_hash,
                raiden=raiden,
                creator_address_for_health_check=participant1
            )
        if is_participant2_handled_lc:
            create_channel(
                block_hash=block_hash,
                block_number=block_number,
                channel_identifier=channel_identifier,
                participant1=participant2,
                participant2=participant1,
                token_network_identifier=token_network_identifier,
                transaction_hash=transaction_hash,
                raiden=raiden,
                creator_address_for_health_check=participant2
            )
    elif raiden.address == participant1:
        create_channel(
            block_hash=block_hash,
            block_number=block_number,
            channel_identifier=channel_identifier,
            participant1=participant1,
            participant2=participant2,
            token_network_identifier=token_network_identifier,
            transaction_hash=transaction_hash,
            raiden=raiden
        )
    elif raiden.address == participant2:
        create_channel(
            block_hash=block_hash,
            block_number=block_number,
            channel_identifier=channel_identifier,
            participant1=participant2,
            participant2=participant1,
            token_network_identifier=token_network_identifier,
            transaction_hash=transaction_hash,
            raiden=raiden
        )
    # Raiden node is not participant of channel. Lc are not participants
    else:
        new_route = ContractReceiveRouteNew(
            transaction_hash=transaction_hash,
            canonical_identifier=CanonicalIdentifier(
                chain_identifier=raiden.chain.network_id,
                token_network_address=token_network_identifier,
                channel_identifier=channel_identifier,
            ),
            participant1=participant1,
            participant2=participant2,
            block_number=block_number,
            block_hash=block_hash,
        )
        raiden.handle_and_track_state_change(new_route)

    # A new channel is available, run the connection manager in case more
    # connections are needed
    connection_manager = raiden.connection_manager_for_token_network(token_network_identifier)
    retry_connect = gevent.spawn(connection_manager.retry_connect)
    raiden.add_pending_greenlet(retry_connect)


def create_channel(block_hash,
                   block_number,
                   channel_identifier,
                   participant1,
                   participant2,
                   token_network_identifier,
                   transaction_hash,
                   raiden,
                   creator_address_for_health_check=None):
    channel_state = create_channel_state_and_proxy(block_number,
                                                   channel_identifier,
                                                   token_network_identifier,
                                                   participant1,
                                                   participant2,
                                                   raiden)
    new_channel = ContractReceiveChannelNew(
        transaction_hash=transaction_hash,
        channel_state=channel_state,
        block_number=block_number,
        block_hash=block_hash,
    )
    raiden.handle_and_track_state_change(new_channel)

    partner_address = channel_state.partner_state.address

    if ConnectionManager.BOOTSTRAP_ADDR != partner_address:
        raiden.start_health_check_for(partner_address, creator_address_for_health_check)

    return channel_state


def create_channel_state_and_proxy(block_number,
                                   channel_identifier,
                                   token_network_identifier,
                                   participant1: ChecksumAddress,
                                   participant2: ChecksumAddress,
                                   raiden):
    is_participant1_handled_lc = LightClientService.is_handled_lc(to_checksum_address(encode_hex(participant1)),
                                                                  raiden.wal)
    is_participant2_handled_lc = LightClientService.is_handled_lc(to_checksum_address(encode_hex(participant2)),
                                                                  raiden.wal)

    channel_proxy = raiden.chain.payment_channel(
        creator_address=participant1,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=views.state_from_raiden(raiden).chain_id,
            token_network_address=token_network_identifier,
            channel_identifier=channel_identifier,
        )
    )
    token_address = channel_proxy.token_address()
    return get_channel_state(
        token_address=typing.TokenAddress(token_address),
        payment_network_identifier=raiden.default_registry.address,
        token_network_address=token_network_identifier,
        reveal_timeout=raiden.config["reveal_timeout"],
        payment_channel_proxy=channel_proxy,
        opened_block_number=block_number,
        is_light_channel=is_participant1_handled_lc or is_participant2_handled_lc,
        both_participants_are_light_clients=is_participant1_handled_lc and is_participant2_handled_lc
    )


def handle_channel_new_balance(raiden: "RaidenService", event: Event):
    data = event.event_data
    args = data["args"]
    block_number = data["block_number"]
    block_hash = data["block_hash"]
    channel_identifier = args["channel_identifier"]
    token_network_identifier = event.originating_contract
    participant_address = args["participant"]
    total_deposit = args["total_deposit"]
    transaction_hash = data["transaction_hash"]

    chain_state = views.state_from_raiden(raiden)
    previous_channel_state = views.get_channelstate_by_canonical_identifier_and_address(
        chain_state=chain_state,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=chain_state.chain_id,
            token_network_address=token_network_identifier,
            channel_identifier=channel_identifier,
        ),
        address=participant_address
    )

    # Channels will only be registered if this node is a participant or LC is a participant
    if previous_channel_state is not None:
        # previous_balance = previous_channel_state.our_state.contract_balance
        # balance_was_zero = previous_balance == 0

        deposit_transaction = TransactionChannelNewBalance(
            participant_address, total_deposit, block_number
        )

        newbalance_statechange = ContractReceiveChannelNewBalance(
            transaction_hash=transaction_hash,
            canonical_identifier=previous_channel_state.canonical_identifier,
            deposit_transaction=deposit_transaction,
            block_number=block_number,
            block_hash=block_hash,
            participant=participant_address
        )
        raiden.handle_and_track_state_change(newbalance_statechange)

        ## TODO mmartinez CHECK THIS AND HANDLE DIFERENTLY FOR LIGHT CLIENTS
        # if balance_was_zero and participant_address != raiden.address:
        #     connection_manager = raiden.connection_manager_for_token_network(
        #         token_network_identifier
        #     )
        #
        #     join_channel = gevent.spawn(
        #         connection_manager.join_channel, participant_address, total_deposit
        #     )
        #
        #     raiden.add_pending_greenlet(join_channel)


def handle_channel_closed(raiden: "RaidenService", event: Event):
    token_network_identifier = event.originating_contract
    data = event.event_data
    block_number = data["block_number"]
    args = data["args"]
    channel_identifier = args["channel_identifier"]
    transaction_hash = data["transaction_hash"]
    block_hash = data["block_hash"]

    chain_state = views.state_from_raiden(raiden)
    channel_state = views.get_channelstate_by_canonical_identifier_and_address(
        chain_state=chain_state,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=chain_state.chain_id,
            token_network_address=token_network_identifier,
            channel_identifier=channel_identifier,
        ),
        address=args['closing_participant'],
    )

    channel_closed: StateChange
    if channel_state:
        # The from address is included in the ChannelClosed event as the
        # closing_participant field
        if raiden.address == channel_state.our_state.address:
            channel_closed = ContractReceiveChannelClosed(
                transaction_hash=transaction_hash,
                transaction_from=args["closing_participant"],
                canonical_identifier=channel_state.canonical_identifier,
                block_number=block_number,
                block_hash=block_hash,
            )
            raiden.handle_and_track_state_change(channel_closed)
        else:
            # Must be a light client
            latest_non_closing_balance_proof = LightClientMessageHandler.get_latest_light_client_non_closing_balance_proof(
                channel_state.identifier, channel_state.our_state.address, raiden.wal.storage
            )
            channel_closed = ContractReceiveChannelClosedLight(
                transaction_hash=transaction_hash,
                transaction_from=args["closing_participant"],
                canonical_identifier=channel_state.canonical_identifier,
                block_number=block_number,
                block_hash=block_hash,
                closing_participant=channel_state.partner_state.address,
                non_closing_participant=channel_state.our_state.address,
                latest_update_non_closing_balance_proof_data=latest_non_closing_balance_proof
            )
            raiden.handle_and_track_state_change(channel_closed)
    else:
        # This is a channel close event of a channel we're not a participant of
        route_closed = ContractReceiveRouteClosed(
            transaction_hash=transaction_hash,
            canonical_identifier=CanonicalIdentifier(
                chain_identifier=chain_state.chain_id,
                token_network_address=token_network_identifier,
                channel_identifier=channel_identifier,
            ),
            block_number=block_number,
            block_hash=block_hash,
        )
        raiden.handle_and_track_state_change(route_closed)


def handle_channel_update_transfer(raiden: "RaidenService", event: Event):
    token_network_identifier = event.originating_contract
    data = event.event_data
    args = data["args"]
    channel_identifier = args["channel_identifier"]
    transaction_hash = data["transaction_hash"]
    block_number = data["block_number"]
    block_hash = data["block_hash"]

    chain_state = views.state_from_raiden(raiden)
    channel_state = views.get_channelstate_by_canonical_identifier_and_address(
        chain_state=chain_state,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=chain_state.chain_id,
            token_network_address=token_network_identifier,
            channel_identifier=channel_identifier,
        ),
        address=args['closing_participant'],
    )

    if channel_state:
        channel_transfer_updated = ContractReceiveUpdateTransfer(
            transaction_hash=transaction_hash,
            canonical_identifier=channel_state.canonical_identifier,
            nonce=args["nonce"],
            block_number=block_number,
            block_hash=block_hash,
        )
        raiden.handle_and_track_state_change(channel_transfer_updated)


def handle_channel_settled(raiden: "RaidenService", event: Event):
    data = event.event_data
    token_network_identifier = event.originating_contract
    channel_identifier = data["args"]["channel_identifier"]
    block_number = data["block_number"]
    block_hash = data["block_hash"]
    transaction_hash = data["transaction_hash"]

    chain_state = views.state_from_raiden(raiden)
    channel_state = get_channelstate_by_canonical_identifier(
        chain_state=chain_state,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=chain_state.chain_id,
            token_network_address=token_network_identifier,
            channel_identifier=channel_identifier,
        ),
        raiden=raiden
    )

    # This may happen for two reasons:
    # - This node is not a participant for the given channel (normal operation,
    #   the event should be ignored).
    # - Something went wrong in our code and the channel state was cleared
    #   before settle (a bug, this should raise an exception on development
    #   mode).
    # Because we cannot distinguish the two cases, assume the channel is not of
    # interest and ignore the event.
    if not channel_state:
        return

    # Recover the locksroot from the blockchain to fix data races. Check
    # get_onchain_locksroots for details.
    try:
        # First try to query the unblinded state. This way the
        # ContractReceiveChannelSettled's locksroots will  match the values
        # provided during settle.
        our_locksroot, partner_locksroot = get_onchain_locksroots(
            chain=raiden.chain,
            canonical_identifier=channel_state.canonical_identifier,
            participant1=channel_state.our_state.address,
            participant2=channel_state.partner_state.address,
            block_identifier=block_hash,
        )
    except ValueError:
        # State pruning handling. The block which generate the ChannelSettled
        # event may have been pruned, because of this the RPC call will raises
        # a ValueError.
        #
        # The solution is to query the channel's state from the latest block,
        # this /may/ create a ContractReceiveChannelSettled with the wrong
        # locksroot (i.e. not the locksroot used during the call to settle).
        # However this is fine, because at this point the channel is settled,
        # it is known that the locksroot can not be reverted without an unlock,
        # and because the unlocks are fare it doesn't matter who called it,
        # only if there are tokens locked in the settled channel.
        our_locksroot, partner_locksroot = get_onchain_locksroots(
            chain=raiden.chain,
            canonical_identifier=channel_state.canonical_identifier,
            participant1=channel_state.our_state.address,
            participant2=channel_state.partner_state.address,
            block_identifier="latest",
        )

    if raiden.address == channel_state.our_state.address:
        channel_settled = ContractReceiveChannelSettled(
            transaction_hash=transaction_hash,
            canonical_identifier=channel_state.canonical_identifier,
            our_onchain_locksroot=our_locksroot,
            partner_onchain_locksroot=partner_locksroot,
            block_number=block_number,
            block_hash=block_hash,
            participant1=channel_state.our_state.address
        )
        raiden.handle_and_track_state_change(channel_settled)
    else:
        channel_settled = ContractReceiveChannelSettledLight(
            transaction_hash=transaction_hash,
            canonical_identifier=channel_state.canonical_identifier,
            our_onchain_locksroot=our_locksroot,
            partner_onchain_locksroot=partner_locksroot,
            block_number=block_number,
            block_hash=block_hash,
            participant1=channel_state.our_state.address,
            participant2=channel_state.partner_state.address
        )
        raiden.handle_and_track_state_change(channel_settled)


def get_our_address_by_canonical_identifier(
    chain_state: ChainState, canonical_identifier: CanonicalIdentifier, raiden: "RaidenService") -> Optional[AddressHex]:
    token_network = get_token_network_by_identifier(
        chain_state, TokenNetworkID(canonical_identifier.token_network_address)
    )
    for address, channels in token_network.channelidentifiers_to_channels.items():
        if canonical_identifier.channel_identifier in channels \
                and (raiden.address == address or raiden.get_light_client_transport(to_checksum_address(address))):
            return address
    return None


def get_channelstate_by_canonical_identifier(
    chain_state: ChainState,
    canonical_identifier: CanonicalIdentifier,
    raiden: "RaidenService") -> Optional[NettingChannelState]:
    address = get_our_address_by_canonical_identifier(chain_state, canonical_identifier, raiden)
    if not address:
        return None
    return views.get_channelstate_by_canonical_identifier_and_address(chain_state,canonical_identifier, address)


def handle_channel_batch_unlock(raiden: "RaidenService", event: Event):
    assert raiden.wal, "The Raiden Service must be initialize to handle events"

    token_network_identifier = event.originating_contract
    data = event.event_data
    args = data["args"]
    block_number = data["block_number"]
    block_hash = data["block_hash"]
    transaction_hash = data["transaction_hash"]
    participant1 = args["participant"]
    participant2 = args["partner"]
    locksroot = args["locksroot"]

    chain_state = views.state_from_raiden(raiden)
    token_network_state = views.get_token_network_by_identifier(
        chain_state, token_network_identifier
    )
    assert token_network_state is not None

    if participant1 == raiden.address:
        partner = participant2
    elif participant2 == raiden.address:
        partner = participant1
    else:
        log.debug(
            "Discarding unlock event, we're not part of it",
            participant1=pex(participant1),
            participant2=pex(participant2),
        )
        return

    channel_identifiers = token_network_state.partneraddresses_to_channelidentifiers[partner]
    canonical_identifier = None

    for channel_identifier in channel_identifiers:
        if partner == args["partner"]:
            state_change_record = get_state_change_with_balance_proof_by_locksroot(
                storage=raiden.wal.storage,
                canonical_identifier=CanonicalIdentifier(
                    chain_identifier=raiden.chain.network_id,
                    token_network_address=token_network_identifier,
                    channel_identifier=channel_identifier,
                ),
                locksroot=locksroot,
                sender=partner,
            )
            if state_change_record.state_change_identifier:
                canonical_identifier = state_change_record.data.balance_proof.canonical_identifier
                break
        elif partner == args["participant"]:
            event_record = get_event_with_balance_proof_by_locksroot(
                storage=raiden.wal.storage,
                canonical_identifier=CanonicalIdentifier(
                    chain_identifier=raiden.chain.network_id,
                    token_network_address=token_network_identifier,
                    channel_identifier=channel_identifier,
                ),
                locksroot=locksroot,
                recipient=partner,
            )
            if event_record.event_identifier:
                canonical_identifier = event_record.data.balance_proof.canonical_identifier
                break

    msg = (
        f"Can not resolve channel_id for unlock with locksroot {pex(locksroot)} and "
        f"partner {pex(partner)}."
    )
    assert canonical_identifier is not None, msg

    unlock_state_change = ContractReceiveChannelBatchUnlock(
        transaction_hash=transaction_hash,
        canonical_identifier=canonical_identifier,
        participant=args["participant"],
        partner=args["partner"],
        locksroot=args["locksroot"],
        unlocked_amount=args["unlocked_amount"],
        returned_tokens=args["returned_tokens"],
        block_number=block_number,
        block_hash=block_hash,
    )

    raiden.handle_and_track_state_change(unlock_state_change)


def handle_secret_revealed(raiden: "RaidenService", event: Event):
    secret_registry_address = event.originating_contract
    data = event.event_data
    args = data["args"]
    block_number = data["block_number"]
    block_hash = data["block_hash"]
    transaction_hash = data["transaction_hash"]
    secret=args["secret"]
    secrethash=args["secrethash"]
    chain_state = views.state_from_raiden(raiden)
    if chain_state.get_payment_task(raiden.address, secrethash):
        registeredsecret_state_change = ContractReceiveSecretReveal(
            transaction_hash=transaction_hash,
            secret_registry_address=secret_registry_address,
            secrethash=secrethash,
            secret=secret,
            block_number=block_number,
            block_hash=block_hash,
        )
        raiden.handle_and_track_state_change(registeredsecret_state_change)
    else:
        for lc_address, payment_state in chain_state.get_payment_states_by_address():
            if secrethash in set(payment_state.secrethashes_to_task):
                registeredsecret_state_change = ContractReceiveSecretRevealLight(
                    transaction_hash=transaction_hash,
                    secret_registry_address=secret_registry_address,
                    secrethash=secrethash,
                    secret=secret,
                    block_number=block_number,
                    block_hash=block_hash,
                    lc_address=lc_address
                )
                raiden.handle_and_track_state_change(registeredsecret_state_change)


def on_blockchain_event(raiden: "RaidenService", event: Event):
    data = event.event_data
    log.debug(
        "Blockchain event",
        node=pex(raiden.address),
        contract=pex(event.originating_contract),
        event_data=data,
    )

    event_name = data["event"]
    if event_name == EVENT_TOKEN_NETWORK_CREATED:
        handle_tokennetwork_new(raiden, event)

    elif event_name == ChannelEvent.OPENED:
        handle_channel_new(raiden, event)

    elif event_name == ChannelEvent.DEPOSIT:
        handle_channel_new_balance(raiden, event)

    elif event_name == ChannelEvent.BALANCE_PROOF_UPDATED:
        handle_channel_update_transfer(raiden, event)

    elif event_name == ChannelEvent.CLOSED:
        handle_channel_closed(raiden, event)

    elif event_name == ChannelEvent.SETTLED:
        handle_channel_settled(raiden, event)

    elif event_name == EVENT_SECRET_REVEALED:
        handle_secret_revealed(raiden, event)

    elif event_name == ChannelEvent.UNLOCKED:
        handle_channel_batch_unlock(raiden, event)

    else:
        log.error("Unknown event type", event_name=data["event"], raiden_event=event)
