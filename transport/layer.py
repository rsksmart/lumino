from typing import List

from transport.node import Node as TransportNode


class Layer:
    """
    Layer centralizes all the transport entities for a Lumino node; it is in effect the transport layer for the system.
    It contains the objects pertaining to both the transport logic for the node behaving as a hub,
    as well as the light client nodes managed by it.
    """

    def __init__(self, hub_transport: TransportNode, light_client_transports: List[TransportNode]):
        self.hub_transport = hub_transport
        self.light_client_transports = light_client_transports

    def add_light_client_transport(self, light_client_transport: TransportNode):
        self.light_client_transports.append(light_client_transport)

    def remove_light_client_transport(self, light_client_transport: TransportNode):
        self.light_client_transports.remove(light_client_transport)
