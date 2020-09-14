from http import HTTPStatus

import structlog
from flask import request

from raiden.api.validations.api_error_builder import ApiErrorBuilder
from raiden.lightclient.handlers.light_client_service import LightClientService

log = structlog.get_logger(__name__)


def requires_api_key(func):
    """
        Check if the endpoint handled by func was called with a valid 'x-api-key' header.
        This decorator requires the class where func is defined to have a property raiden_api,
        of type raiden.api.python.RaidenAPI.
    """
    def inner(*args, **kwargs):
        api_key = request.headers.get("x-api-key")
        if not api_key:
            return ApiErrorBuilder.build_and_log_error(errors="Missing api_key auth header",
                                                       status_code=HTTPStatus.BAD_REQUEST, log=log)
        light_client = LightClientService.get_by_api_key(api_key, args[0].raiden_api.raiden.wal)
        if not light_client:
            return ApiErrorBuilder.build_and_log_error(
                errors="There is no light client associated with the api key provided",
                status_code=HTTPStatus.FORBIDDEN, log=log)
        return func(*args, **kwargs)
    return inner
