from raiden.tests.integration.network.transport.rif_comms.node import Node, Config


class Cluster:
    """
        The Cluster class represents a set of topologies in which RIF Comms bootnode can be tested.
        The topologies includes different scenarios, on each of them, it can be one or more rif comms nodes and clients present.
        For example:
        - Topology A) a rif comms node with two rif comms clients connected
        - Topology B) two rif comms nodes, each of them with one client connected
    """

    def __init__(self, nodes_to_clients: dict):
        """
        The nodes_to_clients dict must respect the following structure:
        {
            "A": 3 // a node with 3 clients connected
            "B": 1 // a node with a client
            "C": 2 // another node with 2 clients connected
        }

        Keys must be letters of the alphabet.
        Values are the amount of clients connected to that node.
        """
        self.nodes_to_clients = nodes_to_clients
        self.nodes = []
        for node_id in nodes_to_clients:
            amount_of_clients = nodes_to_clients[node_id]
            node = Node(Config(node_id, amount_of_clients))
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

    def stop(self):
        for node in self.nodes:
            node.stop()


