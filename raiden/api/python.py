import gevent
import structlog
from gevent import Greenlet
import random
import string
import hashlib
from binascii import hexlify
import os
import dateutil.parser
from datetime import datetime, date
from dateutil.relativedelta import relativedelta
from eth_utils import is_binary_address, to_checksum_address, to_canonical_address, to_normalized_address, decode_hex, \
    encode_hex

from ecies import encrypt, decrypt
from ecies.utils import generate_eth_key, generate_key

import raiden.blockchain.events as blockchain_events
from raiden import waiting
from raiden.api.validations.channel_validator import ChannelValidator
from raiden.constants import (
    GENESIS_BLOCK_NUMBER,
    RED_EYES_PER_TOKEN_NETWORK_LIMIT,
    UINT256_MAX,
    Environment,
    EMPTY_PAYMENT_HASH_INVOICE)
from raiden.exceptions import (
    AlreadyRegisteredTokenAddress,
    ChannelNotFound,
    DepositMismatch,
    DepositOverLimit,
    DuplicatedChannelError,
    InsufficientFunds,
    InsufficientGasReserve,
    InvalidAddress,
    InvalidAmount,
    InvalidSecret,
    InvalidSecretHash,
    InvalidSettleTimeout,
    TokenAppNotFound,
    TokenAppExpired,
    RaidenRecoverableError,
    TokenNotRegistered,
    UnknownTokenAddress,
    InvoiceCoding,
    UnhandledLightClient)
from raiden.lightclient.light_client_message_handler import LightClientMessageHandler
from raiden.lightclient.light_client_service import LightClientService
from raiden.lightclient.light_client_utils import LightClientUtils
from raiden.lightclient.lightclientmessages.hub_message import HubMessage
from raiden.lightclient.lightclientmessages.light_client_payment import LightClientPayment, LightClientPaymentStatus

from raiden.messages import RequestMonitoring, LockedTransfer, RevealSecret, Unlock, Delivered
from raiden.settings import DEFAULT_RETRY_TIMEOUT, DEVELOPMENT_CONTRACT_VERSION
from raiden.transfer import architecture, views, channel
from raiden.transfer.events import (
    EventPaymentReceivedSuccess,
    EventPaymentSentFailed,
    EventPaymentSentSuccess,
)

from raiden.transfer.state import (
    BalanceProofSignedState,
    InitiatorTask,
    MediatorTask,
    NettingChannelState,
    TargetTask,
    TransferTask,
    ChainState)

from raiden.transfer.state_change import ActionChannelClose
from raiden.utils import pex, typing
from raiden.utils.gas_reserve import has_enough_gas_reserve
from raiden.utils.typing import (
    Address,
    AddressHex,
    Any,
    BlockSpecification,
    BlockTimeout,
    ChannelID,
    Dict,
    List,
    LockedTransferType,
    NetworkTimeout,
    Optional,
    PaymentID,
    PaymentNetworkID,
    PaymentHashInvoice,
    Secret,
    SecretHash,
    Set,
    TokenAddress,
    TokenAmount,
    TokenNetworkAddress,
    TokenNetworkID,
    Tuple,
    SignedTransaction, InitiatorAddress, TargetAddress, PaymentWithFeeAmount, BlockExpiration)

from raiden.rns_constants import RNS_ADDRESS_ZERO
from raiden.utils.rns import is_rns_address

from raiden.billing.invoices.options_args import OptionsArgs
from raiden.billing.invoices.util.time_util import get_utc_unix_time, get_utc_expiration_time
from raiden.billing.invoices.encoder.invoice_encoder import parse_options, encode_invoice
from raiden.billing.invoices.decoder.invoice_decoder import decode_invoice
from raiden.utils import random_secret, sha3

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name

EVENTS_PAYMENT_HISTORY_RELATED = (
    EventPaymentSentSuccess,
    EventPaymentSentFailed,
    EventPaymentReceivedSuccess,
)

from raiden.settings import (
    DEFAULT_MATRIX_KNOWN_SERVERS
)

from raiden.utils.cli import get_matrix_servers

from raiden.network.transport.matrix.utils import (
    make_client
)

from urllib.parse import urlparse


def event_filter_for_payments(
    event: architecture.Event,
    token_network_identifier: TokenNetworkID = None,
    partner_address: Address = None,
) -> bool:
    """Filters out non payment history related events
    - If no other args are given, all payment related events match
    - If a token network identifier is given then only payment events for that match
    - If a partner is also given then if the event is a payment sent event and the
      target matches it's returned. If it's a payment received and the initiator matches
      then it's returned.
    """
    is_matching_event = isinstance(event, EVENTS_PAYMENT_HISTORY_RELATED) and (
        token_network_identifier is None
        or token_network_identifier == event.token_network_identifier
    )
    if not is_matching_event:
        return False

    sent_and_target_matches = isinstance(
        event, (EventPaymentSentFailed, EventPaymentSentSuccess)
    ) and (partner_address is None or event.target == partner_address)
    received_and_initiator_matches = isinstance(event, EventPaymentReceivedSuccess) and (
        partner_address is None or event.initiator == partner_address
    )
    return sent_and_target_matches or received_and_initiator_matches


def flatten_transfer(transfer: LockedTransferType, role: str) -> Dict[str, Any]:
    return {
        "payment_identifier": str(transfer.payment_identifier),
        "token_address": to_checksum_address(transfer.token),
        "token_network_identifier": to_checksum_address(
            transfer.balance_proof.token_network_identifier
        ),
        "channel_identifier": str(transfer.balance_proof.channel_identifier),
        "initiator": to_checksum_address(transfer.initiator),
        "target": to_checksum_address(transfer.target),
        "transferred_amount": str(transfer.balance_proof.transferred_amount),
        "locked_amount": str(transfer.balance_proof.locked_amount),
        "role": role,
    }


def get_transfer_from_task(
    secrethash: SecretHash, transfer_task: TransferTask
) -> Tuple[LockedTransferType, str]:
    role = views.role_from_transfer_task(transfer_task)
    transfer: LockedTransferType
    if isinstance(transfer_task, InitiatorTask):
        transfer = transfer_task.manager_state.initiator_transfers[secrethash].transfer
    elif isinstance(transfer_task, MediatorTask):
        pairs = transfer_task.mediator_state.transfers_pair
        if pairs:
            transfer = pairs[-1].payer_transfer
        elif transfer_task.mediator_state.waiting_transfer:
            transfer = transfer_task.mediator_state.waiting_transfer.transfer
    elif isinstance(transfer_task, TargetTask):
        transfer = transfer_task.target_state.transfer
    else:
        raise ValueError("get_tranfer_from_task for a non TransferTask argument")

    return transfer, role


def transfer_tasks_view(
    transfer_tasks: Dict[SecretHash, TransferTask],
    token_address: TokenAddress = None,
    channel_id: ChannelID = None,
) -> List[Dict[str, Any]]:
    view = list()

    for secrethash, transfer_task in transfer_tasks.items():
        transfer, role = get_transfer_from_task(secrethash, transfer_task)

        if transfer is None:
            continue
        if token_address is not None:
            if transfer.token != token_address:
                continue
            elif channel_id is not None:
                if transfer.balance_proof.channel_identifier != channel_id:
                    continue

        view.append(flatten_transfer(transfer, role))

    return view


class RaidenAPI:
    # pylint: disable=too-many-public-methods

    def __init__(self, raiden):
        self.raiden = raiden

    @property
    def address(self):
        return self.raiden.address

    def get_channel(
        self,
        registry_address: PaymentNetworkID,
        token_address: TokenAddress,
        creator_address: Address,
        partner_address: Address,
        channel_id_to_check: ChannelID= None
    ) -> NettingChannelState:
        if not is_binary_address(token_address):
            raise InvalidAddress("Expected binary address format for token in get_channel")

        if not is_binary_address(creator_address):
            raise InvalidAddress("Expected binary address format for creator in get_channel")

        if not is_binary_address(partner_address):
            raise InvalidAddress("Expected binary address format for partner in get_channel")

        channel_list = self.get_channel_list(registry_address, token_address, creator_address, partner_address, channel_id_to_check)
        assert len(channel_list) <= 1

        if not channel_list:
            raise ChannelNotFound(
                "Channel with partner '{}' for token '{}' could not be found.".format(
                    to_checksum_address(partner_address), to_checksum_address(token_address)
                )
            )

        return channel_list[0]

    def validate_token_app(self, token_app):
        token_result = self.get_token_action(token_app)
        result = {}
        if token_result is None:
            raise TokenAppNotFound("Token app not found")
        if isinstance(token_result, tuple):
            result['identifier'] = token_result[0]
            result['token'] = token_result[1]
            result['expires_at'] = token_result[2]
            result['action_request'] = token_result[3]

        expires_at = dateutil.parser.parse(result['expires_at'])
        utc_now = datetime.utcnow()

        diff = utc_now - expires_at
        diff_minutes = diff.total_seconds() / 60
        time_elapsed = diff_minutes - 30
        if time_elapsed > 30:
            raise TokenAppExpired("Token app expired")

    def token_network_register(
        self,
        registry_address: PaymentNetworkID,
        token_address: TokenAddress,
        channel_participant_deposit_limit: TokenAmount,
        token_network_deposit_limit: TokenAmount,
        retry_timeout: NetworkTimeout = DEFAULT_RETRY_TIMEOUT,
    ) -> TokenNetworkAddress:
        """Register the `token_address` in the blockchain. If the address is already
           registered but the event has not been processed this function will block
           until the next block to make sure the event is processed.
        Raises:
            InvalidAddress: If the registry_address or token_address is not a valid address.
            AlreadyRegisteredTokenAddress: If the token is already registered.
            TransactionThrew: If the register transaction failed, this may
                happen because the account has not enough balance to pay for the
                gas or this register call raced with another transaction and lost.
        """

        if not is_binary_address(registry_address):
            raise InvalidAddress("registry_address must be a valid address in binary")

        if not is_binary_address(token_address):
            raise InvalidAddress("token_address must be a valid address in binary")

        if token_address in self.get_tokens_list(registry_address):
            raise AlreadyRegisteredTokenAddress("Token already registered")

        contracts_version = self.raiden.contract_manager.contracts_version

        registry = self.raiden.chain.token_network_registry(registry_address)

        try:
            if contracts_version == DEVELOPMENT_CONTRACT_VERSION:
                return registry.add_token_with_limits(
                    token_address=token_address,
                    channel_participant_deposit_limit=channel_participant_deposit_limit,
                    token_network_deposit_limit=token_network_deposit_limit,
                )
            else:
                return registry.add_token_without_limits(token_address=token_address)
        except RaidenRecoverableError as e:
            if "Token already registered" in str(e):
                raise AlreadyRegisteredTokenAddress("Token already registered")
            # else
            raise

        finally:
            # Assume the transaction failed because the token is already
            # registered with the smart contract and this node has not yet
            # polled for the event (otherwise the check above would have
            # failed).
            #
            # To provide a consistent view to the user, wait one block, this
            # will guarantee that the events have been processed.
            next_block = self.raiden.get_block_number() + 1
            waiting.wait_for_block(self.raiden, next_block, retry_timeout)

    def token_network_connect(
        self,
        registry_address: PaymentNetworkID,
        token_address: TokenAddress,
        funds: TokenAmount,
        initial_channel_target: int = 3,
        joinable_funds_target: float = 0.4,
    ) -> None:
        """ Automatically maintain channels open for the given token network.
        Args:
            token_address: the ERC20 token network to connect to.
            funds: the amount of funds that can be used by the ConnectionMananger.
            initial_channel_target: number of channels to open proactively.
            joinable_funds_target: fraction of the funds that will be used to join
                channels opened by other participants.
        """
        if not is_binary_address(registry_address):
            raise InvalidAddress("registry_address must be a valid address in binary")
        if not is_binary_address(token_address):
            raise InvalidAddress("token_address must be a valid address in binary")

        token_network_identifier = views.get_token_network_identifier_by_token_address(
            chain_state=views.state_from_raiden(self.raiden),
            payment_network_id=registry_address,
            token_address=token_address,
        )

        connection_manager = self.raiden.connection_manager_for_token_network(
            token_network_identifier
        )

        has_enough_reserve, estimated_required_reserve = has_enough_gas_reserve(
            raiden=self.raiden, channels_to_open=initial_channel_target
        )

        if not has_enough_reserve:
            raise InsufficientGasReserve(
                (
                    "The account balance is below the estimated amount necessary to "
                    "finish the lifecycles of all active channels. A balance of at "
                    f"least {estimated_required_reserve} wei is required."
                )
            )

        connection_manager.connect(
            funds=funds,
            initial_channel_target=initial_channel_target,
            joinable_funds_target=joinable_funds_target,
        )

    def token_network_leave(
        self, registry_address: PaymentNetworkID, token_address: TokenAddress
    ) -> List[NettingChannelState]:
        """ Close all channels and wait for settlement. """
        if not is_binary_address(registry_address):
            raise InvalidAddress("registry_address must be a valid address in binary")
        if not is_binary_address(token_address):
            raise InvalidAddress("token_address must be a valid address in binary")

        if token_address not in self.get_tokens_list(registry_address):
            raise UnknownTokenAddress("token_address unknown")

        token_network_identifier = views.get_token_network_identifier_by_token_address(
            chain_state=views.state_from_raiden(self.raiden),
            payment_network_id=registry_address,
            token_address=token_address,
        )

        connection_manager = self.raiden.connection_manager_for_token_network(
            token_network_identifier
        )

        return connection_manager.leave(registry_address)

    def channel_open_light(
        self,
        registry_address: PaymentNetworkID,
        token_address: TokenAddress,
        creator_address: Address,
        partner_address: Address,
        signed_tx: SignedTransaction,
        settle_timeout: BlockTimeout = None,
        retry_timeout: NetworkTimeout = DEFAULT_RETRY_TIMEOUT,
    ) -> ChannelID:
        if settle_timeout is None:
            settle_timeout = self.raiden.config["settle_timeout"]

        token_network = ChannelValidator.can_open_channel(registry_address, token_address, creator_address,
                                                          partner_address, settle_timeout, self.raiden)

        try:
            is_participant1_handled_lc = LightClientService.is_handled_lc(to_checksum_address(creator_address),
                                                                          self.raiden.wal)
            is_participant2_handled_lc = LightClientService.is_handled_lc(to_checksum_address(partner_address),
                                                                          self.raiden.wal)
            if is_participant1_handled_lc or is_participant2_handled_lc:
                token_network.new_netting_channel_light(creator_address, partner_address, signed_tx, settle_timeout,
                                                        given_block_identifier=views.state_from_raiden(
                                                            self.raiden).block_hash)
            else:
                raise UnhandledLightClient("Rejecting channel creation. Light Client isnt registered")

        except DuplicatedChannelError:
            log.info("partner opened channel first")

        waiting.wait_for_newchannel(
            raiden=self.raiden,
            payment_network_id=registry_address,
            token_address=token_address,
            creator_address=creator_address,
            partner_address=partner_address,
            retry_timeout=retry_timeout,
        )
        chain_state = views.state_from_raiden(self.raiden)
        channel_state = views.get_channelstate_for(
            chain_state=chain_state,
            payment_network_id=registry_address,
            token_address=token_address,
            creator_address=creator_address,
            partner_address=partner_address,
        )
        assert channel_state, f"channel {channel_state} is gone"
        return channel_state.identifier

    def channel_open(
        self,
        registry_address: PaymentNetworkID,
        token_address: TokenAddress,
        partner_address: Address,
        settle_timeout: BlockTimeout = None,
        retry_timeout: NetworkTimeout = DEFAULT_RETRY_TIMEOUT,
    ) -> ChannelID:
        """ Open a channel with the peer at `partner_address`
        with the given `token_address`.
        """
        if settle_timeout is None:
            settle_timeout = self.raiden.config["settle_timeout"]
        token_network = ChannelValidator.can_open_channel(registry_address, token_address, self.address,
                                                          partner_address, settle_timeout, self.raiden)
        with self.raiden.gas_reserve_lock:
            ChannelValidator.validate_gas_reserve(1, self.raiden)
            try:
                token_network.new_netting_channel(
                    partner=partner_address,
                    settle_timeout=settle_timeout,
                    given_block_identifier=views.state_from_raiden(self.raiden).block_hash,
                )
            except DuplicatedChannelError:
                log.info("partner opened channel first")

        waiting.wait_for_newchannel(
            raiden=self.raiden,
            payment_network_id=registry_address,
            token_address=token_address,
            creator_address=self.address,
            partner_address=partner_address,
            retry_timeout=retry_timeout,
        )
        chain_state = views.state_from_raiden(self.raiden)
        channel_state = views.get_channelstate_for(
            chain_state=chain_state,
            payment_network_id=registry_address,
            token_address=token_address,
            creator_address=self.address,
            partner_address=partner_address,
        )
        assert channel_state, f"channel {channel_state} is gone"
        return channel_state.identifier

    def _set_total_deposit_preconditions(
        self,
        registry_address: PaymentNetworkID,
        token_address: TokenAddress,
        creator_address: Address,
        partner_address: Address,
        total_deposit: TokenAmount,
        channel_state: NettingChannelState,
        chain_state: ChainState
    ):
        token_addresses = views.get_token_identifiers(chain_state, registry_address)

        if not isinstance(total_deposit, int):
            raise ValueError("total_deposit needs to be an integer number.")

        if not is_binary_address(token_address):
            raise InvalidAddress("Expected binary address format for token in channel deposit")

        if not is_binary_address(creator_address):
            raise InvalidAddress("Expected binary address format for creator in channel deposit")

        if not is_binary_address(partner_address):
            raise InvalidAddress("Expected binary address format for partner in channel deposit")

        if token_address not in token_addresses:
            raise UnknownTokenAddress("Unknown token address")

        if channel_state is None:
            raise InvalidAddress("No channel with partner_address for the given token")

        if self.raiden.config["environment_type"] == Environment.PRODUCTION:
            per_token_network_deposit_limit = RED_EYES_PER_TOKEN_NETWORK_LIMIT
        else:
            per_token_network_deposit_limit = UINT256_MAX

        token = self.raiden.chain.token(token_address)
        token_network_registry = self.raiden.chain.token_network_registry(registry_address)
        token_network_address = token_network_registry.get_token_network(token_address)
        token_network_proxy = self.raiden.chain.token_network(token_network_address)

        if total_deposit == 0:
            raise DepositMismatch("Attempted to deposit with total deposit being 0")

        addendum = total_deposit - channel_state.our_state.contract_balance

        total_network_balance = token.balance_of(registry_address)

        if total_network_balance + addendum > per_token_network_deposit_limit:
            raise DepositOverLimit(
                f"The deposit of {addendum} will exceed the "
                f"token network limit of {per_token_network_deposit_limit}"
            )

        balance = token.balance_of(creator_address)

        functions = token_network_proxy.proxy.contract.functions
        deposit_limit = functions.channel_participant_deposit_limit().call()

        if total_deposit > deposit_limit:
            raise DepositOverLimit(
                f"The additional deposit of {addendum} will exceed the "
                f"channel participant limit of {deposit_limit}"
            )

        # If this check succeeds it does not imply the the `deposit` will
        # succeed, since the `deposit` transaction may race with another
        # transaction.
        if not balance >= addendum:
            msg = "Not enough balance to deposit. {} Available={} Needed={}".format(
                pex(token_address), balance, addendum
            )
            raise InsufficientFunds(msg)

    def set_total_channel_deposit_light(
        self,
        registry_address: PaymentNetworkID,
        token_address: TokenAddress,
        creator_address: Address,
        partner_address: Address,
        signed_approval_tx: SignedTransaction,
        signed_deposit_tx: SignedTransaction,
        total_deposit: TokenAmount,
        retry_timeout: NetworkTimeout = DEFAULT_RETRY_TIMEOUT,
    ):
        """ Set the `total_deposit` in the channel of the 'creator address' with `partner_address` and the
                given `token_address` in order to be able to do transfers.
                Raises:
                    InvalidAddress: If either token_address or partner_address is not
                        20 bytes long.
                    TransactionThrew: May happen for multiple reasons:
                        - If the token approval fails, e.g. the token may validate if
                        account has enough balance for the allowance.
                        - The deposit failed, e.g. the allowance did not set the token
                        aside for use and the user spent it before deposit was called.
                        - The channel was closed/settled between the allowance call and
                        the deposit call.
                    AddressWithoutCode: The channel was settled during the deposit
                        execution.
                    DepositOverLimit: The total deposit amount is higher than the limit.
                """
        chain_state = views.state_from_raiden(self.raiden)

        channel_state = views.get_channelstate_for(
            chain_state=chain_state,
            payment_network_id=registry_address,
            token_address=token_address,
            creator_address=creator_address,
            partner_address=partner_address,
        )

        self._set_total_deposit_preconditions(
            registry_address,
            token_address,
            creator_address,
            partner_address,
            total_deposit,
            channel_state,
            chain_state
        )

        channel_proxy = self.raiden.chain.payment_channel(
            canonical_identifier=channel_state.canonical_identifier
        )

        channel_proxy.set_total_deposit_light(
            total_deposit=total_deposit,
            block_identifier=views.state_from_raiden(self.raiden).block_hash,
            signed_approval_tx=signed_approval_tx,
            signed_deposit_tx=signed_deposit_tx
        )

        waiting.wait_for_participant_newbalance(
            raiden=self.raiden,
            payment_network_id=registry_address,
            token_address=token_address,
            partner_address=partner_address,
            target_address=creator_address,
            target_balance=total_deposit,
            retry_timeout=retry_timeout,
        )

    def set_total_channel_deposit(
        self,
        registry_address: PaymentNetworkID,
        token_address: TokenAddress,
        creator_address: Address,
        partner_address: Address,
        total_deposit: TokenAmount,
        retry_timeout: NetworkTimeout = DEFAULT_RETRY_TIMEOUT,
    ):
        """ Set the `total_deposit` in the channel with the peer at `partner_address` and the
        given `token_address` in order to be able to do transfers.
        Raises:
            InvalidAddress: If either token_address or partner_address is not
                20 bytes long.
            TransactionThrew: May happen for multiple reasons:
                - If the token approval fails, e.g. the token may validate if
                account has enough balance for the allowance.
                - The deposit failed, e.g. the allowance did not set the token
                aside for use and the user spent it before deposit was called.
                - The channel was closed/settled between the allowance call and
                the deposit call.
            AddressWithoutCode: The channel was settled during the deposit
                execution.
            DepositOverLimit: The total deposit amount is higher than the limit.
        """
        chain_state = views.state_from_raiden(self.raiden)

        channel_state = views.get_channelstate_for(
            chain_state=chain_state,
            payment_network_id=registry_address,
            token_address=token_address,
            creator_address=creator_address,
            partner_address=partner_address,
        )
        self._set_total_deposit_preconditions(
            registry_address,
            token_address,
            creator_address,
            partner_address,
            total_deposit,
            channel_state,
            chain_state
        )

        channel_proxy = self.raiden.chain.payment_channel(
            canonical_identifier=channel_state.canonical_identifier
        )

        # set_total_deposit calls approve
        # token.approve(netcontract_address, addendum)
        channel_proxy.set_total_deposit(
            total_deposit=total_deposit,
            block_identifier=views.state_from_raiden(self.raiden).block_hash,
        )

        waiting.wait_for_participant_newbalance(
            raiden=self.raiden,
            payment_network_id=registry_address,
            token_address=token_address,
            partner_address=partner_address,
            target_address=creator_address,
            target_balance=total_deposit,
            retry_timeout=retry_timeout,
        )

    def channel_close(
        self,
        registry_address: PaymentNetworkID,
        token_address: TokenAddress,
        partner_address: Address,
        retry_timeout: NetworkTimeout = DEFAULT_RETRY_TIMEOUT,
    ):
        """Close a channel opened with `partner_address` for the given
        `token_address`.
        Race condition, this can fail if channel was closed externally.
        """
        self.channel_batch_close(
            registry_address=registry_address,
            token_address=token_address,
            partner_addresses=[partner_address],
            retry_timeout=retry_timeout,
        )

    def channel_close_light(
        self,
        registry_address: PaymentNetworkID,
        token_address: TokenAddress,
        partner_address: Address,
        retry_timeout: NetworkTimeout = DEFAULT_RETRY_TIMEOUT,
        signed_close_tx: typing.SignedTransaction = None,
    ):
        """Close a channel opened with `partner_address` for the given
        `token_address`.
        Race condition, this can fail if channel was closed externally.
        """
        self.channel_batch_close_light(
            registry_address=registry_address,
            token_address=token_address,
            partner_addresses=[partner_address],
            retry_timeout=retry_timeout,
            signed_close_tx=signed_close_tx
        )

    def channel_batch_close_light(
        self,
        registry_address: PaymentNetworkID,
        token_address: TokenAddress,
        partner_addresses: List[Address],
        retry_timeout: NetworkTimeout = DEFAULT_RETRY_TIMEOUT,
        signed_close_tx: typing.SignedTransaction = None,
    ):
        """Close a channel opened with `partner_address` for the given
        `token_address`.
        Race condition, this can fail if channel was closed externally.
        """

        channels_to_close = ChannelValidator.can_close_channel(
            token_address,
            partner_addresses,
            registry_address,
            self.raiden)

        self.delegate_channel_close_task(channels_to_close, signed_close_tx)

        channel_ids = [channel_state.identifier for channel_state in channels_to_close]

        waiting.wait_for_close(
            raiden=self.raiden,
            payment_network_id=registry_address,
            token_address=token_address,
            channel_ids=channel_ids,
            retry_timeout=retry_timeout,
            partner_addresses=partner_addresses
        )

    def delegate_channel_close_task(self, channels_to_close, signed_close_tx=None):
        greenlets: Set[Greenlet] = set()
        for channel_state in channels_to_close:
            channel_close = ActionChannelClose(
                canonical_identifier=channel_state.canonical_identifier,
                signed_close_tx=signed_close_tx,
                participant1=channel_state.our_state.address,
                participant2=channel_state.partner_state.address
            )

            greenlets.update(self.raiden.handle_state_change(channel_close))

        gevent.joinall(greenlets, raise_error=True)

    def channel_batch_close(
        self,
        registry_address: PaymentNetworkID,
        token_address: TokenAddress,
        partner_addresses: List[Address],
        retry_timeout: NetworkTimeout = DEFAULT_RETRY_TIMEOUT,
    ):
        """Close a channel opened with `partner_address` for the given
        `token_address`.
        Race condition, this can fail if channel was closed externally.
        """

        channels_to_close = ChannelValidator.can_close_channel(
            token_address,
            partner_addresses,
            registry_address,
            self.raiden)

        self.delegate_channel_close_task(channels_to_close)

        channel_ids = [channel_state.identifier for channel_state in channels_to_close]

        waiting.wait_for_close(
            raiden=self.raiden,
            payment_network_id=registry_address,
            token_address=token_address,
            channel_ids=channel_ids,
            retry_timeout=retry_timeout,
            partner_addresses=partner_addresses,
        )

    def get_channel_list(
        self,
        registry_address: PaymentNetworkID,
        token_address: TokenAddress = None,
        creator_address: Address = None,
        partner_address: Address = None,
        channel_id_to_check: ChannelID = None
    ) -> List[NettingChannelState]:
        """Returns a list of channels associated with the optionally given
           `token_address` and/or `partner_address`.
        Args:
            token_address: an optionally provided token address
            creator_address: an optionally provided creator address
            partner_address: an optionally provided partner address
        Return:
            A list containing all channels the node participates. Optionally
            filtered by a token address and/or partner address.
        Raises:
            KeyError: An error occurred when the token address is unknown to the node.
        """
        if registry_address and not is_binary_address(registry_address):
            raise InvalidAddress("Expected binary address format for registry in get_channel_list")

        if token_address and not is_binary_address(token_address):
            raise InvalidAddress("Expected binary address format for token in get_channel_list")

        if partner_address and creator_address:
            if not is_binary_address(partner_address):
                raise InvalidAddress(
                    "Expected binary address format for partner in get_channel_list"
                )
            if not is_binary_address(creator_address):
                raise InvalidAddress(
                    "Expected binary address format for creator in get_channel_list"
                )
            if not token_address:
                raise UnknownTokenAddress("Provided a partner address but no token address")

        if token_address and partner_address and creator_address:

            if channel_id_to_check is not None:
                channel_state = views.get_channelstate_for_close_channel(
                    chain_state=views.state_from_raiden(self.raiden),
                    payment_network_id=registry_address,
                    token_address=token_address,
                    creator_address=creator_address,
                    partner_address=partner_address,
                    channel_id_to_check=channel_id_to_check
                )
            else:
                channel_state = views.get_channelstate_for(
                    chain_state=views.state_from_raiden(self.raiden),
                    payment_network_id=registry_address,
                    token_address=token_address,
                    creator_address=creator_address,
                    partner_address=partner_address
                )

            if channel_state:
                result = [channel_state]
            else:
                result = []

        elif token_address:
            result = views.list_channelstate_for_tokennetwork(
                chain_state=views.state_from_raiden(self.raiden),
                payment_network_id=registry_address,
                token_address=token_address,
            )

        else:
            result = views.list_all_channelstate(chain_state=views.state_from_raiden(self.raiden))

        return result

    def get_channel_list_for_tokens(
        self,
        registry_address: typing.PaymentNetworkID,
        token_addresses: typing.ByteString = None,
    ) -> typing.List[NettingChannelState]:
        """Returns a list of channels associated with the mandatory given
           `token_addresses`.
        Args:
            token_addresses: an mandatory provided token list addresses
        Return:
            A list containing all channels the node participates, filtered by a token address
        Raises:
            KeyError: An error occurred when the token address is unknown to the node.
        """
        if registry_address and not is_binary_address(registry_address):
            raise InvalidAddress('Expected binary address format for registry in get_channel_list')

        token_addresses_split = token_addresses.split(",")
        if isinstance(token_addresses_split, list):
            for token_address in token_addresses_split:
                self._check_token_address_format(to_canonical_address(token_address))

            result = views.list_channelstate_for_tokennetwork_lumino(
                chain_state=views.state_from_raiden(self.raiden),
                payment_network_id=registry_address,
                token_addresses_split=token_addresses_split,
                node_address=self.address
            )

        return result

    def _check_token_address_format(self, token_address):
        if token_address and not is_binary_address(token_address):
            raise InvalidAddress('Expected binary address format for token in get_channel_list')

    def get_node_network_state(self, node_address: typing.Address):
        """ Returns the currently network status of `node_address`. """
        return views.get_node_network_status(
            chain_state=views.state_from_raiden(self.raiden), node_address=node_address
        )

    def start_health_check_for(self, node_address: Address):
        """ Returns the currently network status of `node_address`. """
        self.raiden.start_health_check_for(node_address)

    def get_tokens_list(self, registry_address: PaymentNetworkID):
        """Returns a list of tokens the node knows about"""
        tokens_list = views.get_token_identifiers(
            chain_state=views.state_from_raiden(self.raiden), payment_network_id=registry_address
        )
        return tokens_list

    def get_token_network_address_for_token_address(
        self, registry_address: PaymentNetworkID, token_address: TokenAddress
    ) -> Optional[TokenNetworkID]:
        return views.get_token_network_identifier_by_token_address(
            chain_state=views.state_from_raiden(self.raiden),
            payment_network_id=registry_address,
            token_address=token_address,
        )

    def transfer_and_wait(
        self,
        registry_address: PaymentNetworkID,
        token_address: TokenAddress,
        amount: TokenAmount,
        target: Address,
        identifier: PaymentID = None,
        transfer_timeout: int = None,
        secret: Secret = None,
        secrethash: SecretHash = None,
        payment_hash_invoice: PaymentHashInvoice = None
    ):
        """ Do a transfer with `target` with the given `amount` of `token_address`. """
        # pylint: disable=too-many-arguments
        payment_status = self.transfer_async(

            registry_address=registry_address,
            token_address=token_address,
            amount=amount,
            target=target,
            identifier=identifier,
            secret=secret,
            secrethash=secrethash,
            payment_hash_invoice=payment_hash_invoice
        )
        payment_status.payment_done.wait(timeout=transfer_timeout)
        return payment_status

    def transfer_async(
        self,
        registry_address: PaymentNetworkID,
        token_address: TokenAddress,
        amount: TokenAmount,
        target: Address,
        identifier: PaymentID = None,
        secret: Secret = None,
        secrethash: SecretHash = None,
        payment_hash_invoice: PaymentHashInvoice = None
    ):
        current_state = views.state_from_raiden(self.raiden)
        payment_network_identifier = self.raiden.default_registry.address

        if not isinstance(amount, int):
            raise InvalidAmount("Amount not a number")

        if amount <= 0:
            raise InvalidAmount("Amount negative")

        if amount > UINT256_MAX:
            raise InvalidAmount("Amount too large")

        if not is_binary_address(token_address):
            raise InvalidAddress("token address is not valid.")

        if token_address not in views.get_token_identifiers(current_state, registry_address):
            raise UnknownTokenAddress("Token address is not known.")

        if not is_binary_address(target):
            raise InvalidAddress("target address is not valid.")

        valid_tokens = views.get_token_identifiers(
            views.state_from_raiden(self.raiden), registry_address
        )
        if token_address not in valid_tokens:
            raise UnknownTokenAddress("Token address is not known.")

        if secret is not None and not isinstance(secret, typing.T_Secret):
            raise InvalidSecret("secret is not valid.")

        if secrethash is not None and not isinstance(secrethash, typing.T_SecretHash):
            raise InvalidSecretHash("secrethash is not valid.")

        log.debug(
            "Initiating transfer",
            initiator=pex(self.raiden.address),
            target=pex(target),
            token=pex(token_address),
            amount=amount,
            identifier=identifier,
            payment_hash_invoice=payment_hash_invoice
        )

        token_network_identifier = views.get_token_network_identifier_by_token_address(
            chain_state=current_state,
            payment_network_id=payment_network_identifier,
            token_address=token_address,
        )
        payment_status = self.raiden.mediated_transfer_async(
            token_network_identifier=token_network_identifier,
            amount=amount,
            target=target,
            identifier=identifier,
            secret=secret,
            secrethash=secrethash,
            payment_hash_invoice=payment_hash_invoice
        )
        return payment_status

    def transfer_async_light(
        self,
        registry_address: PaymentNetworkID,
        token_address: TokenAddress,
        amount: TokenAmount,
        creator: Address,
        target: Address,
        identifier: PaymentID,
        secrethash: SecretHash,
        signed_locked_transfer: LockedTransfer,
        payment_hash_invoice: PaymentHashInvoice = None
    ):
        current_state = views.state_from_raiden(self.raiden)
        payment_network_identifier = self.raiden.default_registry.address

        if not isinstance(amount, int):
            raise InvalidAmount("Amount not a number")

        if amount <= 0:
            raise InvalidAmount("Amount negative")

        if amount > UINT256_MAX:
            raise InvalidAmount("Amount too large")

        if not is_binary_address(token_address):
            raise InvalidAddress("token address is not valid.")

        if token_address not in views.get_token_identifiers(current_state, registry_address):
            raise UnknownTokenAddress("Token address is not known.")

        if not is_binary_address(target):
            raise InvalidAddress("target address is not valid.")

        valid_tokens = views.get_token_identifiers(
            views.state_from_raiden(self.raiden), registry_address
        )
        if token_address not in valid_tokens:
            raise UnknownTokenAddress("Token address is not known.")

        if secrethash is not None and not isinstance(secrethash, typing.T_SecretHash):
            raise InvalidSecretHash("secrethash is not valid.")

        log.debug(
            "Initiating transfer light",
            initiator=pex(creator),
            target=pex(target),
            token=pex(token_address),
            amount=amount,
            identifier=identifier,
            payment_hash_invoice=payment_hash_invoice
        )

        token_network_identifier = views.get_token_network_identifier_by_token_address(
            chain_state=current_state,
            payment_network_id=payment_network_identifier,
            token_address=token_address,
        )
        payment_status = self.raiden.mediated_transfer_async_light(
            token_network_identifier=token_network_identifier,
            amount=amount,
            creator=creator,
            target=target,
            identifier=identifier,
            secrethash=secrethash,
            payment_hash_invoice=payment_hash_invoice,
            signed_locked_transfer=signed_locked_transfer
        )
        return None

    def initiate_send_secret_reveal_light(self, sender_address: typing.Address, receiver_address: typing.Address,
                                          reveal_secret: RevealSecret):
        self.raiden.initiate_send_secret_reveal_light(sender_address, receiver_address, reveal_secret)

    def initiate_send_balance_proof(self, sender_address: typing.Address, receiver_address: typing.Address,
                                          unlock: Unlock):
        self.raiden.initiate_send_balance_proof(sender_address, receiver_address, unlock)

    def initiate_send_delivered_light(self, sender_address: typing.Address, receiver_address: typing.Address,
                                      delivered: Delivered, msg_order: int, payment_id: int):
        self.raiden.initiate_send_delivered_light(sender_address, receiver_address, delivered, msg_order, payment_id)


    def get_raiden_events_payment_history_with_timestamps_v2(
        self,
        token_network_identifier: typing.Address = None,
        initiator_address: typing.TokenAddress = None,
        target_address: typing.Address = None,
        from_date: typing.LogTime = None,
        to_date: typing.LogTime = None,
        event_type: int = None,
        limit: int = None,
        offset: int = None,
    ):

        events = [
            event
            for event in self.raiden.wal.storage.get_payment_events(
                token_network_identifier=token_network_identifier,
                our_address=to_normalized_address(self.raiden.address),
                initiator_address=initiator_address,
                target_address=target_address,
                from_date=from_date,
                to_date=to_date,
                event_type=event_type,
                limit=limit,
                offset=offset,
            )
        ]

        for event in events:
            chain_state = views.state_from_raiden(self.raiden)
            for payment_network in chain_state.identifiers_to_paymentnetworks.values():
                for token_network in payment_network.tokenidentifiers_to_tokennetworks.values():
                    if token_network.address == event.wrapped_event.token_network_identifier:
                        setattr(event.wrapped_event, 'token_address',
                                to_normalized_address(token_network.token_address))

        return events

    def get_raiden_events_payment_history_with_timestamps(
        self,
        token_address: TokenAddress = None,
        target_address: Address = None,
        limit: int = None,
        offset: int = None,
    ):
        if token_address and not is_binary_address(token_address):
            raise InvalidAddress(
                "Expected binary address format for token in get_raiden_events_payment_history"
            )

        if target_address and not is_binary_address(target_address):
            raise InvalidAddress(
                "Expected binary address format for "
                "target_address in get_raiden_events_payment_history"
            )

        token_network_identifier = None
        if token_address:
            token_network_identifier = views.get_token_network_identifier_by_token_address(
                chain_state=views.state_from_raiden(self.raiden),
                payment_network_id=self.raiden.default_registry.address,
                token_address=token_address,
            )

        events = [
            event
            for event in self.raiden.wal.storage.get_events_with_timestamps(
                limit=limit, offset=offset
            )
            if event_filter_for_payments(
                event=event.wrapped_event,
                token_network_identifier=token_network_identifier,
                partner_address=target_address,
            )
        ]

        return events

    def get_dashboard_data(self, graph_from_date, graph_to_date, table_limit: int = None):
        result = self.raiden.wal.storage.get_dashboard_data(graph_from_date, graph_to_date, table_limit)

        return result

    def get_raiden_events_payment_history(
        self,
        token_address: TokenAddress = None,
        target_address: Address = None,
        limit: int = None,
        offset: int = None,
    ):
        timestamped_events = self.get_raiden_events_payment_history_with_timestamps(
            token_address=token_address, target_address=target_address, limit=limit, offset=offset
        )

        return [event.wrapped_event for event in timestamped_events]

    def get_raiden_internal_events_with_timestamps(self, limit: int = None, offset: int = None):
        return self.raiden.wal.storage.get_events_with_timestamps(limit=limit, offset=offset)

    transfer = transfer_and_wait

    def get_invoice(self, payment_hash):
        invoice = self.raiden.wal.storage.query_invoice(payment_hash)
        return invoice

    def decode_invoice(self, coded_invoice):
        return decode_invoice(coded_invoice)

    def get_blockchain_events_network(
        self,
        registry_address: PaymentNetworkID,
        from_block: BlockSpecification = GENESIS_BLOCK_NUMBER,
        to_block: BlockSpecification = "latest",
    ):
        events = blockchain_events.get_token_network_registry_events(
            chain=self.raiden.chain,
            token_network_registry_address=registry_address,
            contract_manager=self.raiden.contract_manager,
            events=blockchain_events.ALL_EVENTS,
            from_block=from_block,
            to_block=to_block,
        )

        return sorted(events, key=lambda evt: evt.get("block_number"), reverse=True)

    def get_blockchain_events_token_network(
        self,
        token_address: TokenAddress,
        from_block: BlockSpecification = GENESIS_BLOCK_NUMBER,
        to_block: BlockSpecification = "latest",
    ):
        """Returns a list of blockchain events coresponding to the token_address."""

        if not is_binary_address(token_address):
            raise InvalidAddress(
                "Expected binary address format for token in get_blockchain_events_token_network"
            )

        token_network_address = self.raiden.default_registry.get_token_network(token_address)

        if token_network_address is None:
            raise UnknownTokenAddress("Token address is not known.")

        returned_events = blockchain_events.get_token_network_events(
            chain=self.raiden.chain,
            token_network_address=token_network_address,
            contract_manager=self.raiden.contract_manager,
            events=blockchain_events.ALL_EVENTS,
            from_block=from_block,
            to_block=to_block,
        )

        for event in returned_events:
            if event.get("args"):
                event["args"] = dict(event["args"])

        returned_events.sort(key=lambda evt: evt.get("block_number"), reverse=True)
        return returned_events

    def get_blockchain_events_channel(
        self,
        token_address: TokenAddress,
        partner_address: Address = None,
        from_block: BlockSpecification = GENESIS_BLOCK_NUMBER,
        to_block: BlockSpecification = "latest",
    ):
        if not is_binary_address(token_address):
            raise InvalidAddress(
                "Expected binary address format for token in get_blockchain_events_channel"
            )
        token_network_address = self.raiden.default_registry.get_token_network(token_address)
        if token_network_address is None:
            raise UnknownTokenAddress("Token address is not known.")

        channel_list = self.get_channel_list(
            registry_address=self.raiden.default_registry.address,
            token_address=token_address,
            partner_address=partner_address,
        )
        returned_events = []
        for channel in channel_list:
            returned_events.extend(
                blockchain_events.get_all_netting_channel_events(
                    chain=self.raiden.chain,
                    token_network_address=token_network_address,
                    netting_channel_identifier=channel.identifier,
                    contract_manager=self.raiden.contract_manager,
                    from_block=from_block,
                    to_block=to_block,
                )
            )
        returned_events.sort(key=lambda evt: evt.get("block_number"), reverse=True)
        return returned_events

    def create_monitoring_request(
        self, balance_proof: BalanceProofSignedState, reward_amount: TokenAmount
    ) -> Optional[RequestMonitoring]:
        """ This method can be used to create a `RequestMonitoring` message.
        It will contain all data necessary for an external monitoring service to
        - send an updateNonClosingBalanceProof transaction to the TokenNetwork contract,
        for the `balance_proof` that we received from a channel partner.
        - claim the `reward_amount` from the UDC.
        """
        # create RequestMonitoring message from the above + `reward_amount`
        monitor_request = RequestMonitoring.from_balance_proof_signed_state(
            balance_proof=balance_proof, reward_amount=reward_amount
        )
        # sign RequestMonitoring and return
        monitor_request.sign(self.raiden.signer)
        return monitor_request

    def get_pending_transfers(
        self, token_address: TokenAddress = None, partner_address: Address = None
    ) -> List[Dict[str, Any]]:
        chain_state = views.state_from_raiden(self.raiden)
        transfer_tasks = views.get_all_transfer_tasks(chain_state)
        channel_id = None

        if token_address is not None:
            if self.raiden.default_registry.get_token_network(token_address) is None:
                raise UnknownTokenAddress(f"Token {token_address} not found.")
            if partner_address is not None:
                partner_channel = self.get_channel(
                    registry_address=self.raiden.default_registry.address,
                    token_address=token_address,
                    creator_address=self.address,
                    partner_address=partner_address,
                    channel_id_to_check=None
                )
                channel_id = partner_channel.identifier

        return transfer_tasks_view(transfer_tasks, token_address, channel_id)

    def get_network_graph(self, token_network_address):
        chain_state = views.state_from_raiden(self.raiden)
        token_network_state = views.get_token_network_by_identifier(
            chain_state=chain_state,
            token_network_id=token_network_address
        )
        return token_network_state.network_graph

    def write_token_action(self, action):

        # Generate a expiration date with 30 minutes in the future
        expires_at = datetime.utcnow() - relativedelta(minutes=30)

        expires_at_iso_format = expires_at.isoformat()

        # Generate a random string of letters, digits and timeStamp
        letters_and_digits = string.ascii_letters + string.digits
        random_characters = ''.join(random.choice(letters_and_digits) for i in range(30))

        hash_result = hashlib.new("sha1",
                                  str(expires_at.timestamp()).encode('utf-8') + str(random_characters).encode('utf-8'))

        token_data = {"token": hash_result.hexdigest(), "expires_at": expires_at_iso_format, "action_request": action}

        # Save this information
        self.raiden.wal.storage.write_token_action(token_data)

        return token_data

    def get_token_action(self, token):
        token_data = self.raiden.wal.storage.query_token_action(token)
        return token_data

    def update_invoice(self, data):
        # Update this information
        self.raiden.wal.storage.update_invoice(data)

    def create_invoice(self, data):
        if data['already_coded_invoice']:
            persisted_invoice = self.persist_invoice(data)
        else:
            persisted_invoice = self.do_encode_invoce(data)

        return persisted_invoice

    def persist_invoice(self, data):
        # Save this information
        self.raiden.wal.storage.write_invoice(data)

        return data

    def do_encode_invoce(self, data):

        if not is_binary_address(data['token_address']):
            raise InvalidAddress("Expected binary address format for token in create_invoice")

        if not is_binary_address(data['partner_address']):
            raise InvalidAddress("Expected binary address format for partner in create_invoice")

        chain = self.raiden.chain
        private_key = chain.client.privkey.hex()
        timestamp = get_utc_unix_time()

        timestamp_utc_str = datetime.utcfromtimestamp(timestamp).isoformat()

        currency = data['currency_symbol']
        fallback = None
        amount = data['amount']
        invoice_secret = random_secret()
        payment_hash = sha3(invoice_secret)
        payment_hash = encode_hex(payment_hash)

        description = data['description']
        description_hashed = None
        expires = data['expires']
        route = []
        beneficiary = "0x" + data['partner_address'].hex()
        token = "0x" + data['token_address'].hex()

        options_args = OptionsArgs(timestamp,
                                   currency,
                                   fallback,
                                   amount,
                                   payment_hash,
                                   description,
                                   description_hashed,
                                   expires,
                                   route,
                                   private_key,
                                   beneficiary,
                                   token)

        lumino_invoice_obj = parse_options(options_args)

        try:
            lumino_invoice_encoded = encode_invoice(lumino_invoice_obj, options_args.privkey)
        except TypeError:
            raise InvoiceCoding("Error coding the invoice, review the input data provided")

        expiration_date = get_utc_expiration_time(expires)

        return self.persist_invoice({"type": data['invoice_type'],
                                     "status": data['invoice_status'],
                                     "expiration_date": expiration_date,
                                     "encode": lumino_invoice_encoded,
                                     "payment_hash": payment_hash,
                                     "secret": encode_hex(invoice_secret),
                                     "currency": currency,
                                     "amount": str(amount),
                                     "description": description,
                                     "target_address": beneficiary,
                                     "token_address": token,
                                     "created_at": timestamp_utc_str})

    def search_lumino(self, registry_address: typing.PaymentNetworkID, query, only_receivers):

        channel_identifiers_by_token_network = []
        node_addresses_by_token_network = []
        token_addresses = self._get_token_addresses_for_search(registry_address)

        chain_state = views.state_from_raiden(self.raiden)

        for payment_network in chain_state.identifiers_to_paymentnetworks.values():
            for token_network in payment_network.tokenidentifiers_to_tokennetworks.values():
                node_addresses = self._get_node_addresses_for_search(token_network)
                if len(node_addresses) > 0:
                    node_addresses_by_token_network.append(node_addresses)
                channel_identifiers = self._get_channel_identifiers_for_search(token_network)
                if len(channel_identifiers) > 0:
                    channel_identifiers_by_token_network.append(channel_identifiers)

        result_search = self._search_in(channel_identifiers_by_token_network, node_addresses_by_token_network,
                                        token_addresses, query, only_receivers)

        # First we check if the address received is an RNS address or a hexadecimal address
        if is_rns_address(query):
            rns_resolved_address = self.raiden.chain.get_address_from_rns(query)
            if rns_resolved_address != RNS_ADDRESS_ZERO:
                result_search["rns_address_matches"].append(rns_resolved_address)

        return {"results": result_search}

    def _search_in(self, channel_identifiers, node_addresses, token_addresses, query, only_receivers):
        result_search = {"token_address_matches": [],
                         "node_address_matches": [],
                         "channel_identifiers_matches": [],
                         "rns_address_matches": []}

        if only_receivers:
            result_search["node_address_matches"] = self._get_matches_for_search(node_addresses, query)
        else:
            result_search["node_address_matches"] = self._get_matches_for_search(node_addresses, query)
            result_search["channel_identifiers_matches"] = self._get_matches_for_search(channel_identifiers, query)
            result_search["token_address_matches"] = self._get_matches_for_search(token_addresses, query)

        return result_search

    def _get_matches_for_search(self, data, query):
        matches = []

        if len(data) > 0:
            if isinstance(data[0], list):
                for data_token_network in data:
                    match_in_result = self._match_in(data_token_network, query)
                    if len(match_in_result) > 0:
                        matches.extend(match_in_result)
                # Remove repeated elements
                if len(matches) > 0:
                    if not isinstance(matches[0], dict):
                        matches = list(dict.fromkeys(matches))
            else:
                matches = self._match_in(data, query)

        return matches

    def _match_in(self, data, query):
        matches = []
        for item in data:
            if isinstance(item, dict):
                for key, value in item.items():
                    if query in value:
                        matches.append(item)
                # Remove duplicate dicts
                matches = [dict(t) for t in {tuple(d.items()) for d in matches}]
            else:
                if query in item:
                    matches.append(item)
        return matches

    def _get_channel_identifiers_for_search(self, token_network):
        channels = []
        if self.address in token_network.channelidentifiers_to_channels:
            channels_objects = token_network.channelidentifiers_to_channels[self.address].values()
            for channel in channels_objects:
                channel_info = {"id": str(channel.identifier),
                                "token_address": to_checksum_address(channel.token_address),
                                "token_network_identifier": to_checksum_address(channel.token_network_identifier),
                                "partner_address": to_checksum_address(channel.partner_state.address)}
                channels.append(channel_info)

        return channels

    def _get_token_addresses_for_search(self, registry_address):
        token_addresses = []
        token_list = self.get_tokens_list(registry_address)

        for token in token_list:
            token_addresses.append(to_checksum_address("0x" + token.hex()))

        return token_addresses

    def _get_node_addresses_for_search(self, token_network):
        node_addresses = []
        nodes = token_network.network_graph.channel_identifier_to_participants.values()
        for node_address_tuple in nodes:
            for address in node_address_tuple:
                node_addresses.append(to_checksum_address("0x" + address.hex()))

        return node_addresses

    def get_all_light_clients(self):
        light_clients = self.raiden.wal.storage.get_all_light_clients()
        return light_clients

    def get_data_for_registration_request(self, address):
        # fetch list of known servers from raiden-network/raiden-tranport repo
        available_servers_url = DEFAULT_MATRIX_KNOWN_SERVERS[self.raiden.config["environment_type"]]
        available_servers = get_matrix_servers(available_servers_url)
        client = make_client(available_servers)
        server_url = client.api.base_url
        server_name = urlparse(server_url).netloc
        data_to_sign = {
            "display_name_to_sign": "@" + to_normalized_address(address) + ":" + server_name,
            "password_to_sign": server_name,
            "seed_retry": "seed"}
        return data_to_sign

    def register_light_client(self,
                              address,
                              signed_password,
                              signed_display_name,
                              signed_seed_retry):

        address = to_checksum_address(address)

        light_client = self.raiden.wal.storage.get_light_client(address)

        if light_client is None:

            api_key = hexlify(os.urandom(20))
            api_key = api_key.decode("utf-8")

            pubhex = self.raiden.config["pubkey"].hex()
            encrypt_signed_password = encrypt(pubhex, signed_password.encode())
            encrypt_signed_display_name = encrypt(pubhex, signed_display_name.encode())
            encrypt_signed_seed_retry = encrypt(pubhex, signed_seed_retry.encode())

            result = self.raiden.wal.storage.save_light_client(
                api_key=api_key,
                address=address,
                encrypt_signed_password=encrypt_signed_password.hex(),
                encrypt_signed_display_name=encrypt_signed_display_name.hex(),
                encrypt_signed_seed_retry=encrypt_signed_seed_retry.hex())

            if result > 0:
                result = {"address": address,
                          "encrypt_signed_password": encrypt_signed_password.hex(),
                          "encrypt_signed_display_name": encrypt_signed_display_name.hex(),
                          "api_key": api_key,
                          "encrypt_signed_seed_retry": encrypt_signed_seed_retry.hex(),
                          "message": "successfully registered",
                          "result_code": 0}
            else:
                result = {"message": "An unexpected error has occurred.",
                          "result_code": 1}
        else:
            result = {"message": "The client you are trying to register has already registered.",
                      "result_code": 2}

        return result

    def create_light_client_payment(
        self,
        registry_address: typing.PaymentNetworkID,
        creator_address: typing.AddressHex,
        partner_address: typing.AddressHex,
        token_address: typing.TokenAddress,
        amount: typing.TokenAmount,
        secrethash: typing.SecretHash
    ) -> HubMessage:
        channel_state = views.get_channelstate_for(
            views.state_from_raiden(self.raiden),
            registry_address,
            token_address,
            creator_address,
            partner_address,
        )
        if channel_state:
            chain_state = views.state_from_raiden(self.raiden)
            # Build autogenerated values
            lt_autogenerated_values = LightClientUtils.build_lt_autogen_values(chain_state, channel_state)
            # Create locked transfer event
            locked_transfer, merkle_tree_state = channel.create_sendlockedtransfer(
                channel_state,
                InitiatorAddress(creator_address),
                TargetAddress(partner_address),
                PaymentWithFeeAmount(amount),
                lt_autogenerated_values.message_identifier,
                lt_autogenerated_values.payment_identifier,
                EMPTY_PAYMENT_HASH_INVOICE,
                BlockExpiration(1624776),
                secrethash)


            # Get the LockedTransfer message
            locked_transfer = LockedTransfer.from_event(locked_transfer)
            # Create the light_client_payment
            is_lc_initiator = 1
            payment = LightClientPayment(creator_address, partner_address,
                                         is_lc_initiator, channel_state.token_network_identifier,
                                         amount,
                                         str(date.today()),
                                         LightClientPaymentStatus.Pending,
                                         locked_transfer.payment_identifier)
            # Persist the light_client_protocol_message associated
            order = 0
            payment_row_id = LightClientMessageHandler.store_light_client_payment(payment, self.raiden.wal)
            light_client_message_id = LightClientMessageHandler.store_light_client_protocol_message(
                locked_transfer.message_identifier,
                locked_transfer,
                False,
                payment.payment_id,
                order,
                self.raiden.wal
            )

            return HubMessage(payment.payment_id, order, locked_transfer)
        else:
            raise ChannelNotFound("Channel with given partner address doesnt exists")

