from transport.rif_comms.node import RifCommsNode
from transport.layer import Layer as TransportLayer


class RifCommsLayer(TransportLayer[RifCommsNode]):

    def construct_full_node(self, config):
        return RifCommsNode(config["address"], config["transport"]["rif_comms"])

    def construct_light_clients_nodes(self, config):
        pass


