class ClientException(Exception):
    """
    An Exception that represents an error occurred between the interaction between the RIFCommsClient and
    RIF Comms pubsub bootnode.

    The ClientException has the following attributes, that are created from the RpcError ones:
        - code: corresponds to the RpcError.code()
        - message: corresponds to the RpcError.details()
    """

    def __init__(self, code, message):
        super().__init__(f"Code: {code}, Message: {message}")
        self.code = code
        self.message = message


class InvalidArgumentException(ClientException):
    """
    An argument passed to the operation was invalid
    """


class InternalException(ClientException):
    """
    There was an internal error on the RIF Comms pubsub bootnode
    """


class NotFoundException(ClientException):
    """
    Address wasnt found on the DHT of the RIF Comms pubsub bootnode
    """


class FailedPreconditionException(ClientException):
    """
    A RIF Comms pubsub bootnode precondition failed
    """


class TimeoutException(ClientException):
    """
    Request to RIF Comms pubsub bootnode took too long to finish
    """
