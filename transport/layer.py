from abc import ABC, abstractmethod
from typing import List, Dict, Any
from typing import TypeVar, Generic

from raiden.utils import Address
from transport.node import Node as TransportNode

TN = TypeVar('TN', bound=TransportNode)


class Layer(ABC, Generic[TN]):
    """
    Layer is an abstraction which centralizes all the transport entities for a Lumino node; it is in effect the
    transport layer for the system.
    It contains the objects pertaining to both the transport logic for the running node, acting as a full node or a hub,
    as well as any nodes registered as light clients to be managed.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the transport layer based on the received configuration in the form of an arbitrary dictionary.
        This constructor delegates the construction of the transport nodes for the running node and registered light clients
        in the transport layer.
        """
        self._full_node = self.construct_full_node(config)
        self._light_clients = self.construct_light_clients_nodes(config)

    def add_light_client(self, light_client_transport: TN):
        self.light_clients.append(light_client_transport)

    def remove_light_client(self, light_client_transport: TN):
        self.light_clients.remove(light_client_transport)

    @property
    def full_node(self) -> TN:
        return self._full_node

    @property
    def light_clients(self) -> List[TN]:
        return self._light_clients

    @abstractmethod
    def light_client_onboarding_data(self, address: Address) -> dict:
        """
        Return the onboarding info necessary for registering light clients on the transport layer.
        """

    @abstractmethod
    def register_light_client(self, raiden_api: 'RaidenAPI', registration_data: dict) -> TransportNode:
        """
        Register a light client on the transport layer.
        """

    @abstractmethod
    def construct_full_node(self, config):
        """
         This function must return a subtype of TransportNode
        """

    @abstractmethod
    def construct_light_clients_nodes(self, config):
        """
         This function must return a list of objects that are subtype of TransportNode
        """
