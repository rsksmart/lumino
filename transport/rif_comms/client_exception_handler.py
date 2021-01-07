from typing import Union

from grpc import RpcError, StatusCode

from transport.rif_comms.exceptions import ClientException, TimeoutException, InternalException, \
    InvalidArgumentException, NotFoundException, FailedPreconditionException


class ClientExceptionHandler:
    EXCEPTION_MAPPING = {
        StatusCode.DEADLINE_EXCEEDED: TimeoutException,
        StatusCode.INTERNAL: InternalException,
        StatusCode.INVALID_ARGUMENT: InvalidArgumentException,
        StatusCode.NOT_FOUND: NotFoundException,
        StatusCode.FAILED_PRECONDITION: FailedPreconditionException
    }

    @classmethod
    def get_exception(cls, rpc_error: RpcError) -> Union[RpcError, ClientException]:
        exception = cls.EXCEPTION_MAPPING.get(rpc_error.code(), ClientException)
        return exception(code=rpc_error.code(), message=rpc_error.details())
