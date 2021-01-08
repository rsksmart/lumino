from transport.layer import Layer as TransportLayer
from transport.matrix.layer import MatrixLayer as MatrixTransportLayer


class Config:
    """
    Config is a placeholder class used to choose between transport layer implementations for Lumino.
    """

    def __init__(self, transport_layer: TransportLayer):
        self.transport_layer = transport_layer


# Matrix is hard-coded as the chosen implementation for now
cfg = Config(MatrixTransportLayer)
