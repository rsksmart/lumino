from raiden.tests.integration.network.transport.rif_comms.node import Node, Config


class Cluster:
    def __init__(self, nodes_to_clients: dict):
        self.nodes_to_clients = nodes_to_clients
        self.nodes = list()
        for cluster_key in nodes_to_clients:
            amount_of_clients = nodes_to_clients[cluster_key]
            node = Node(Config(cluster_key, amount_of_clients))
            self.nodes.append(node)

    def get_clients(self) -> dict:
        """
        Aux function to flatten comms clients.
        @returns a dict of clients. Each key is the client number to access
        on each test. The value is a RIFCommsClient instance.
        """
        cluster_clients = {}
        for comms_node in self.nodes:
            for client in comms_node.clients:
                cluster_clients[len(cluster_clients.keys()) + 1] = client
        return cluster_clients

    def shutdown(self):
        for node in self.nodes:
            node.stop()
