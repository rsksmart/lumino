from raiden.network.transport import MatrixTransport
from raiden.network.transport.matrix import MatrixLightClientTransport

from transport.layer import TransportLayer


class Config:
    def __init__(self, hub_transport_class: TransportLayer, light_client_transport_class: TransportLayer):
        self.hub_transport_class = hub_transport_class
        self.light_client_transport_class = light_client_transport_class


# placeholder config-like setting
cfg = Config(MatrixTransport, MatrixLightClientTransport)
