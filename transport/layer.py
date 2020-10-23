from abc import ABC, abstractmethod
from typing import List, Dict, Any

from raiden.utils import Address
from transport.node import Node as TransportNode


class Layer(ABC):
    """
    Layer is an abstraction which centralizes all the transport entities for a Lumino node; it is in effect the
    transport layer for the system.
    It contains the objects pertaining to both the transport logic for the running node, acting as a full node or a hub,
    as well as any nodes registered as light clients to be managed.
    """

    @abstractmethod
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the transport layer based on the received configuration in the form of an arbitrary dictionary.
        This constructor should ultimately set the transport nodes for the running node and registered light clients
        in the transport layer.
        """

    @property
    @abstractmethod
    def full_node(self) -> TransportNode:
        """
        Return the transport node corresponding to the running Lumino node, acting as a full node or hub.
        """

    @property
    @abstractmethod
    def light_clients(self) -> List[TransportNode]:
        """
        Return the transport nodes for every light client registered in the running Lumino node.
        """

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
    def add_light_client(self, light_client_transport: TransportNode):
        """
        Add a light client transport node to the layer.
        """

    @abstractmethod
    def remove_light_client(self, light_client_transport: TransportNode):
        """
        Remove a light client transport node from the layer.
        """
