from raiden.network.transport import MatrixTransport
from raiden.network.transport.matrix import MatrixLightClientTransport

from transport.layer import Layer as TransportLayer


class Config:
    """
    Config is a placeholder class used to choose between transport layer implementations for Lumino.
    """

    def __init__(self, hub_transport_class: TransportLayer, light_client_transport_class: TransportLayer):
        self.hub_transport_class = hub_transport_class
        self.light_client_transport_class = light_client_transport_class


# Matrix is hard-coded as the chosen implementation for now
cfg = Config(MatrixTransport, MatrixLightClientTransport)
