from http import HTTPStatus

from eth_utils import is_binary_address, to_checksum_address

from raiden.api.validations.api_error_builder import ApiErrorBuilder
from raiden.api.validations.validation_result import TokenExists, EnoughBalance
from raiden.exceptions import AddressWithoutCode, InvalidSettleTimeout, InvalidAddress, DuplicatedChannelError, \
    TokenNotRegistered, InsufficientGasReserve, UnknownTokenAddress, DepositMismatch, DepositOverLimit, \
    InsufficientFunds
from raiden.network.blockchain_service import BlockChainService
from raiden.network.proxies import Token, TokenNetworkRegistry, TokenNetwork
from raiden.transfer import views
from raiden.transfer.state import NettingChannelState
from raiden.utils import typing, pex
from raiden.utils.gas_reserve import has_enough_gas_reserve
from raiden.utils.typing import PaymentNetworkID, TokenAddress, Address, BlockTimeout, TokenAmount, List, Optional


class ChannelValidator:
    @staticmethod
    def validate_token_exists(chain: BlockChainService, token_address: typing.TokenAddress, log) -> TokenExists:
        try:
            return TokenExists(None, True, chain.token(token_address))
        except AddressWithoutCode as e:
            return TokenExists(ApiErrorBuilder.build_error(errors=str(e), status_code=HTTPStatus.CONFLICT, log=log),
                               False, None)

    @staticmethod
    def enough_balance_to_deposit(total_deposit: typing.TokenAmount, address: typing.Address, token: Token, log) -> EnoughBalance:
        balance = token.balance_of(address)
        if total_deposit is not None and total_deposit > balance:
            error_msg = "Not enough balance to deposit. {} Available={} Needed={}".format(
                pex(token.address), balance, total_deposit
            )
            return EnoughBalance(ApiErrorBuilder.build_error(errors=error_msg, status_code=HTTPStatus.PAYMENT_REQUIRED, log=log)
                                 , True, balance)
        return EnoughBalance(None, True, balance)

    @staticmethod
    def can_open_channel(registry_address: PaymentNetworkID, token_address: TokenAddress, creator_address: Address, partner_address: Address,
                           settle_timeout: BlockTimeout, raiden) -> TokenNetwork:

        if settle_timeout < raiden.config["reveal_timeout"] * 2:
            raise InvalidSettleTimeout(
                "settle_timeout can not be smaller than double the reveal_timeout"
            )

        if not is_binary_address(registry_address):
            raise InvalidAddress("Expected binary address format for registry in channel open")

        if not is_binary_address(token_address):
            raise InvalidAddress("Expected binary address format for token in channel open")

        if not is_binary_address(partner_address):
            raise InvalidAddress("Expected binary address format for partner in channel open")

        if not is_binary_address(creator_address):
            raise InvalidAddress("Expected binary address format for creator in channel open")

        chain_state = views.state_from_raiden(raiden)
        # The node is the creator
        if creator_address == raiden.address:
            channel_state = views.get_channelstate_for(
                chain_state=chain_state,
                payment_network_id=registry_address,
                token_address=token_address,
                partner_address=partner_address,
            )
            if channel_state:
                raise DuplicatedChannelError("Channel with given partner address already exists")
        else:
            # A light client creates the channel
            exists = views.get_channel_existence_from_network_participants(chain_state, registry_address, token_address,
                                                                           creator_address, partner_address)
            if exists:
                raise DuplicatedChannelError("Channel with given partner address already exists")

        registry: TokenNetworkRegistry = raiden.chain.token_network_registry(registry_address)
        token_network = raiden.chain.token_network(registry.get_token_network(token_address))

        if token_network is None:
            raise TokenNotRegistered(
                "Token network for token %s does not exist" % to_checksum_address(token_address)
            )
        return token_network

    @staticmethod
    def validate_gas_reserve(channels_to_open: int, raiden) -> int:
        has_enough_reserve, estimated_required_reserve = has_enough_gas_reserve(
            raiden, channels_to_open
        )
        if not has_enough_reserve:
            raise InsufficientGasReserve(
                (
                    "The account balance is below the estimated amount necessary to "
                    "finish the lifecycles of all active channels. A balance of at "
                    f"least {estimated_required_reserve} wei is required."
                )
            )
        return estimated_required_reserve

    @staticmethod
    def can_set_total_channel_deposit(channel_state: Optional[NettingChannelState] ,token_address: TokenAddress, token_addresses: List[TokenAddress], partner_address: Address, total_deposit: TokenAmount):
        if not is_binary_address(token_address):
            raise InvalidAddress("Expected binary address format for token in channel deposit")

        if not is_binary_address(partner_address):
            raise InvalidAddress("Expected binary address format for partner in channel deposit")

        if token_address not in token_addresses:
            raise UnknownTokenAddress("Unknown token address")

        if channel_state is None:
            raise InvalidAddress("No channel with partner_address for the given token")

        if total_deposit == 0:
            raise DepositMismatch("Attempted to deposit with total deposit being 0")

    @staticmethod
    def validate_deposit_amount(total_network_balance: TokenAmount, added: TokenAmount, per_token_network_deposit_limit: TokenAmount
                                    ,total_deposit: TokenAmount, token: Token, address: Address, token_network_proxy: TokenNetwork):
        if total_network_balance + added > per_token_network_deposit_limit:
            raise DepositOverLimit(
                f"The deposit of {added} will exceed the "
                f"token network limit of {per_token_network_deposit_limit}"
            )

        balance = token.balance_of(address)

        functions = token_network_proxy.proxy.contract.functions
        deposit_limit = functions.channel_participant_deposit_limit().call()

        if total_deposit > deposit_limit:
            raise DepositOverLimit(
                f"The additional deposit of {added} will exceed the "
                f"channel participant limit of {deposit_limit}"
            )

            # If this check succeeds it does not imply the the `deposit` will
            # succeed, since the `deposit` transaction may race with another
            # transaction.
        if not balance >= added:
            msg = "Not enough balance to deposit. {} Available={} Needed={}".format(
                pex(token.address), balance, added
            )
            raise InsufficientFunds(msg)




