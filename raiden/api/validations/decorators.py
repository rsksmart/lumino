from http import HTTPStatus
import structlog
from flask import request
from raiden.api.validations.api_error_builder import ApiErrorBuilder
from raiden.exceptions import InsufficientFunds, RawTransactionFailed, InvalidPaymentIdentifier, ChannelNotFound, \
    UnhandledLightClient
from raiden.lightclient.handlers.light_client_service import LightClientService

log = structlog.get_logger(__name__)


def requires_api_key(func):
    """
        Check if the endpoint handled by func was called with a valid 'x-api-key' header.
        This decorator requires the class where func is defined to have a property raiden_api,
        of type raiden.api.python.RaidenAPI.
    """

    def inner(rest_api: "RestAPI", *args, **kwargs):
        api_key = request.headers.get("x-api-key")
        if not api_key:
            return ApiErrorBuilder.build_and_log_error(
                errors="Missing api_key auth header", status_code=HTTPStatus.BAD_REQUEST, log=log
            )
        light_client = LightClientService.get_by_api_key(api_key=api_key, wal=rest_api.raiden_api.raiden.wal)
        if not light_client:
            return ApiErrorBuilder.build_and_log_error(
                errors="There is no light client associated with the api key provided",
                status_code=HTTPStatus.FORBIDDEN,
                log=log
            )
        return func(rest_api, *args, **kwargs)

    return inner


def requires_lc_balance(func):
    """
        Check if the endpoint handled by func was called with a Lc that has balance greater than 0.
    """
    @requires_api_key
    def inner(rest_api: "RestAPI", *args, **kwargs):
        api_key = request.headers.get("x-api-key")
        raiden_api = rest_api.raiden_api
        light_client = LightClientService.get_by_api_key(api_key=api_key, wal=raiden_api.raiden.wal)
        web3 = raiden_api.raiden.default_registry.client.web3
        current_lc_balance = web3.eth.getBalance(light_client.address)
        if current_lc_balance > 0:
            return func(rest_api, *args, **kwargs)
        return ApiErrorBuilder.build_and_log_error(
            errors="Insufficient Funds",
            status_code=HTTPStatus.PAYMENT_REQUIRED,
            log=log
        )
    return inner


def api_safe_operation(is_light_client=False, lc_balance_required=False):
    """
        Executes an operation and never crashes the node, instead it always respond with an error code.
    """
    def default_decorator(func):
        def default_inner(rest_api: "RestAPI", *args, **kwargs):
            return func(rest_api, *args, **kwargs)
        return default_inner

    def get_inner(func, decorator=default_decorator):
        @decorator
        def inner(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except InsufficientFunds as e:
                return ApiErrorBuilder.build_and_log_error(errors=str(e),
                                                           status_code=HTTPStatus.PAYMENT_REQUIRED,
                                                           log=log)
            except (RawTransactionFailed, InvalidPaymentIdentifier) as e:
                return ApiErrorBuilder.build_and_log_error(errors=str(e),
                                                           status_code=HTTPStatus.BAD_REQUEST,
                                                           log=log)
            except ChannelNotFound as e:
                return ApiErrorBuilder.build_and_log_error(errors=str(e),
                                                           status_code=HTTPStatus.NOT_FOUND,
                                                           log=log)
            except UnhandledLightClient as e:
                return ApiErrorBuilder.build_and_log_error(errors=str(e),
                                                           status_code=HTTPStatus.FORBIDDEN,
                                                           log=log)
            except Exception as e:
                return ApiErrorBuilder.build_and_log_error(errors=str(e),
                                                           status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
                                                           log=log)
        return inner

    if is_light_client:
        if lc_balance_required:
            def safe_light_operation(func):
                return get_inner(func=func, decorator=requires_lc_balance)
            return safe_light_operation
        else:
            def safe_light_operation(func):
                return get_inner(func=func, decorator=requires_api_key)
            return safe_light_operation
    else:
        def safe_operation(func):
            return get_inner(func)
        return safe_operation
