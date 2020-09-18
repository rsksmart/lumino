from raiden.network.transport import MatrixTransport
from raiden.network.transport.matrix import MatrixLightClientTransport

from transport.layer import TransportLayer


class Config:
    def __init__(self, hub_transport: TransportLayer, light_client_transport: TransportLayer):
        self.hub_transport = hub_transport
        self.light_client_transport = light_client_transport


# placeholder config-like setting
cfg = Config(MatrixTransport, MatrixLightClientTransport)
