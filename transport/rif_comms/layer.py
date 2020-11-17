from raiden.utils import Address
from transport.node import Node as TransportNode
from transport.rif_comms.node import RifCommsNode
from transport.layer import Layer as TransportLayer


class RifCommsLayer(TransportLayer[RifCommsNode]):

    def construct_full_node(self, config):
        return RifCommsNode(config["address"], config["transport"]["rif_comms"])

    def construct_light_clients_nodes(self, config):
        return []

    def light_client_onboarding_data(self, address: Address) -> dict:
        pass

    def register_light_client(self, raiden_api: 'RaidenAPI', registration_data: dict) -> TransportNode:
        pass

