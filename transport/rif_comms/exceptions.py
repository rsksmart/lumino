from abc import ABC, abstractmethod
from typing import Union

from grpc import RpcError, StatusCode


class ClientException(Exception, ABC):

    @property
    @abstractmethod
    def get_code(self):
        """
        return the code property
        """

    @property
    @abstractmethod
    def get_message(self):
        """
        return the code property
        """

    def __str__(self):
        message = super(ClientException, self).__str__()
        return f"Code: {self.get_code}, Message: {message}"


class InvalidArgumentException(ClientException):
    def __init__(self, code, message):
        self.code = code
        self.message = message
        super(InvalidArgumentException, self).__init__(message)

    def get_code(self):
        return self.code

    def get_message(self):
        return self.message


class InternalException(ClientException):
    def __init__(self, code, message):
        self.code = code
        self.message = message
        super(InternalException, self).__init__(message)

    def get_code(self):
        return self.code

    def get_message(self):
        return self.message


class NotFoundException(ClientException):
    def __init__(self, code, message):
        self.code = code
        self.message = message
        super(NotFoundException, self).__init__(message)

    def get_code(self):
        return self.code

    def get_message(self):
        return self.message


class FailedPreconditionException(ClientException):
    def __init__(self, code, message):
        self.code = code
        self.message = message
        super(FailedPreconditionException, self).__init__(message)

    def get_code(self):
        return self.code

    def get_message(self):
        return self.message


class TimeoutException(ClientException):
    def __init__(self, code, message):
        self.code = code
        self.message = message
        super(TimeoutException, self).__init__(message)

    def get_code(self):
        return self.code

    def get_message(self):
        return self.message


EXCEPTION_MAPPING = {
    StatusCode.DEADLINE_EXCEEDED: TimeoutException,
    StatusCode.INTERNAL: InternalException,
    StatusCode.INVALID_ARGUMENT: InvalidArgumentException,
    StatusCode.NOT_FOUND: NotFoundException,
    StatusCode.FAILED_PRECONDITION: FailedPreconditionException
}


def client_handled_operation(func):
    def inner(client: "Client", *args, **kwargs):
        try:
            return func(client, *args, **kwargs)
        except RpcError as error:
            raise get_exception(error)
    return inner


def get_exception(rpc_error: RpcError) -> Union[RpcError, ClientException]:
    if rpc_error.code() in EXCEPTION_MAPPING and EXCEPTION_MAPPING.get(rpc_error.code()):
        exception = EXCEPTION_MAPPING.get(rpc_error.code())
        return exception(code=rpc_error.code(), message=rpc_error.details())
    return rpc_error

