from flask import make_response
from raiden.api.validations.api_status_codes import ERROR_STATUS_CODES
import json


class ApiErrorBuilder:
    @staticmethod
    def build_error(errors, status_code, log):
        assert status_code in ERROR_STATUS_CODES, "Programming error, unexpected error status code"
        if log:
            log.error("Error processing request", errors=errors, status_code=status_code)
        response = make_response(
            (
                json.dumps(dict(errors=errors)),
                status_code,
                {"mimetype": "application/json", "Content-Type": "application/json"},
            )
        )
        return response

