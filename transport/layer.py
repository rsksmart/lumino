from abc import ABC, abstractmethod
from typing import List, Dict, Any

from raiden.utils import Address
from transport.node import Node as TransportNode


class Layer(ABC):
    """
    Layer is an abstraction which centralizes all the transport entities for a Lumino node; it is in effect the
    transport layer for the system.
    It contains the objects pertaining to both the transport logic for the node behaving as a hub, as well as any nodes
    registered as light clients to be managed.
    """

    @abstractmethod
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the transport layer based on the received configuration in the form of an arbitrary dictionary.
        This constructor should ultimately set the hub and light client transport nodes in the transport layer.
        """

    @property
    @abstractmethod
    def hub_transport(self) -> TransportNode:
        """
        Return the transport node corresponding to the running Lumino node, acting as a hub or regular node.
        """

    @property
    @abstractmethod
    def light_client_transports(self) -> List[TransportNode]:
        """
        Return the transport nodes for every light client registered in the running Lumino node.
        """

    @staticmethod
    @abstractmethod
    def new_light_client_transport(address: Address, config: Dict[str, Any]) -> TransportNode:
        """
        Instantiate a new transport node for a light client to be registered on the transport layer.
        """

    @abstractmethod
    def add_light_client_transport(self, light_client_transport: TransportNode):
        """
        Add a light client transport node to the layer.
        """

    @abstractmethod
    def remove_light_client_transport(self, light_client_transport: TransportNode):
        """
        Remove a light client transport node from the layer.
        """
