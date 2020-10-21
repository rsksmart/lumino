from raiden.network.transport.matrix.layer import MatrixLayer as MatrixTransportLayer

from transport.layer import Layer as TransportLayer


class Factory:
    """
    Factory is a class used to choose between transport layer implementations for Lumino.
    """

    def __init__(self, transport_layer: TransportLayer):
        self.transport_layer = transport_layer

    @staticmethod
    def create(transport_type : str, config : dict):
        if transport_type == "rif-comms":
            raise Exception("not implemented yet!")
        elif transport_type == "matrix":
            return MatrixTransportLayer(config)


# Matrix is hard-coded as the chosen implementation for now
factory = Factory(MatrixTransportLayer)
