from http import HTTPStatus

import structlog
from flask import request

from raiden.api.validations.api_error_builder import ApiErrorBuilder
from raiden.api.validations.light_client_authorization import get_key_error
from raiden.lightclient.handlers.light_client_service import LightClientService

log = structlog.get_logger(__name__)


def requires_lc_balance(func):
    """
        Check if the endpoint handled by func was called with a Lc that has balance greater than 0.
    """
    def inner(*args, **kwargs):
        raiden_api = args[0].raiden_api
        key_error = get_key_error(raiden_api.raiden.wal)
        if key_error:
            return key_error
        api_key = request.headers.get("x-api-key")
        light_client = LightClientService.get_by_api_key(api_key=api_key, wal=raiden_api.raiden.wal)
        web3 = raiden_api.raiden.default_registry.client.web3
        current_lc_balance = web3.eth.getBalance(light_client.address)
        if current_lc_balance > 0:
            return func(*args, **kwargs)
        return ApiErrorBuilder.build_and_log_error(
            errors="Insufficient Funds",
            status_code=HTTPStatus.PAYMENT_REQUIRED,
            log=log
        )
    return inner
