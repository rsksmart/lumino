from http import HTTPStatus

from eth_utils import is_binary_address, to_checksum_address

from raiden.api.validations.api_error_builder import ApiErrorBuilder
from raiden.api.validations.validation_result import TokenExists, EnoughBalance
from raiden.exceptions import AddressWithoutCode, InvalidSettleTimeout, InvalidAddress, DuplicatedChannelError, \
    TokenNotRegistered
from raiden.network.blockchain_service import BlockChainService
from raiden.network.proxies import Token, TokenNetworkRegistry, TokenNetwork
from raiden.transfer import views
from raiden.utils import typing, pex
from raiden.utils.typing import PaymentNetworkID, TokenAddress, Address, BlockTimeout


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
    def can_channel_open(registry_address: PaymentNetworkID, token_address: TokenAddress, partner_address: Address,
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

        chain_state = views.state_from_raiden(raiden)
        channel_state = views.get_channelstate_for(
            chain_state=chain_state,
            payment_network_id=registry_address,
            token_address=token_address,
            partner_address=partner_address,
        )

        if channel_state:
            raise DuplicatedChannelError("Channel with given partner address already exists")

        registry: TokenNetworkRegistry = raiden.chain.token_network_registry(registry_address)
        token_network_address = registry.get_token_network(token_address)

        if token_network_address is None:
            raise TokenNotRegistered(
                "Token network for token %s does not exist" % to_checksum_address(token_address)
            )
        token_network = raiden.chain.token_network(registry.get_token_network(token_address))
        return token_network


