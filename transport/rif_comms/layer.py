from typing import Any, Dict, List

from raiden.utils import Address
from transport.layer import Layer as TransportLayer
from transport.node import Node as TransportNode
from transport.rif_comms.node import RifCommsLightClientNode as RifCommsLightClientTransportNode


class RifCommsLayer(TransportLayer):
    def __init__(self, config: Dict[str, Any]):
        pass

    @property
    def full_node(self) -> TransportNode:
        return self._full_node

    @property
    def light_clients(self) -> List[TransportNode]:
        return self._light_clients

    @staticmethod
    def new_light_client(address: Address, config: dict, auth_params: dict) -> TransportNode:
        return RifCommsLightClientTransportNode(address, config, auth_params)

    def add_light_client(self, light_client_transport: TransportNode):
        self._light_clients.append(light_client_transport)

    def remove_light_client(self, light_client_transport: TransportNode):
        self._light_clients.remove(light_client_transport)
