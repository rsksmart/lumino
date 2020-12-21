from http import HTTPStatus

import structlog
import traceback

from raiden.api.validations.api_error_builder import ApiErrorBuilder
from raiden.api.validations.light_client_authorization import requires_api_key
from raiden.exceptions import InsufficientFunds

log = structlog.get_logger(__name__)


def lc_safe_operation(func):
    """
        Executes an lc operation and never pull down the node, instead it always respond with an error code.
    """
    @requires_api_key
    def inner(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except InsufficientFunds as e:
            return ApiErrorBuilder.build_and_log_error(
                errors=str(e),
                status_code=HTTPStatus.PAYMENT_REQUIRED,
                log=log
            )
        except Exception as e:
            traceback.print_exc()
            return ApiErrorBuilder.build_and_log_error(
                errors=str(e),
                status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
                log=log
            )
    return inner
