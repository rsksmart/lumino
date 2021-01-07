
class ClientException(Exception):

    def __init__(self, code, message):
        super().__init__(f"Code: {code}, Message: {message}")
        self.code = code
        self.message = message


class InvalidArgumentException(ClientException):
    """

    """


class InternalException(ClientException):
    """

    """


class NotFoundException(ClientException):
    """

    """


class FailedPreconditionException(ClientException):
    """

    """


class TimeoutException(ClientException):
    """

    """

