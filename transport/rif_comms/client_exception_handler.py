from typing import Union

from grpc import RpcError, StatusCode

from transport.rif_comms.exceptions import ClientException, TimeoutException, InternalException, \
    InvalidArgumentException, NotFoundException, FailedPreconditionException


class ClientExceptionHandler:
    """
        A class to map RPC exceptions to RIF Comms client exceptions.
    """
    EXCEPTION_MAPPING = {
        StatusCode.DEADLINE_EXCEEDED: TimeoutException,
        StatusCode.INTERNAL: InternalException,
        StatusCode.INVALID_ARGUMENT: InvalidArgumentException,
        StatusCode.NOT_FOUND: NotFoundException,
        StatusCode.FAILED_PRECONDITION: FailedPreconditionException
    }

    @classmethod
    def map_exception(cls, rpc_error: RpcError) -> Union[RpcError, ClientException]:
        """
            This function maps an RpcError exception into a custom ClientException
        """
        exception = cls.EXCEPTION_MAPPING.get(rpc_error.code(), ClientException)
        return exception(code=rpc_error.code(), message=rpc_error.details())
