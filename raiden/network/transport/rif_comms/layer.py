from raiden.network.transport.rif_comms import RifCommsNode, RifCommsLightClientNode
from raiden.utils import Address
from transport.layer import Layer as TransportLayer
from transport.node import Node as TransportNode


class RifCommsLayer(TransportLayer[RifCommsNode]):

    def construct_full_node(self, config):
        return RifCommsNode(config["address"], config["transport"]["rif_comms"])

    def construct_light_clients_nodes(self, config):
        pass

    @staticmethod
    def new_light_client(address: Address, config: dict, auth_params: dict) -> TransportNode:
        return RifCommsLightClientNode(address, config, auth_params)
