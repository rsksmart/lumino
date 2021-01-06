from abc import ABC, abstractmethod


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




