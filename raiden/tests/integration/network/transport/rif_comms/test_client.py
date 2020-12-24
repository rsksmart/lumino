import pytest

from raiden.tests.integration.network.transport.rif_comms.node import Node as CommsNode, Config as CommsConfig
from raiden.tests.integration.network.transport.utils import generate_address


@pytest.fixture()
@pytest.mark.parametrize("cluster")
def comms_clients(cluster: dict) -> {int, CommsNode}:
    """
    The cluster dict has the following structure:

    {
        1: 3 // a node with 3 clients connected
        2: 1 // a node with a client
        3: 2 // another node with 2 clients connected
    }

    Keys must be in increasing order from 1 to N
    Values are the amount of clients connected to that node.
    """

    def get_all_clients_from_cluster_nodes(comms_nodes: list) -> dict:
        """
        Aux function to flatten comms clients.
        @param comms_nodes a list of CommsNode object
        @returns a dict of clients. Each key is the client number to access
        on each test. The value is a RIFCommsClient instance.
        """
        cluster_clients = {}
        for comms_node in comms_nodes:
            for client in comms_node.clients:
                cluster_clients[len(cluster_clients.keys()) + 1] = client
        return cluster_clients

    nodes = list()
    # setup
    for cluster_key in cluster:
        amount_of_clients = cluster[cluster_key]
        node = CommsNode(CommsConfig(cluster_key, amount_of_clients))
        nodes.append(node)
    all_clients = get_all_clients_from_cluster_nodes(nodes)
    yield all_clients

    # teardown
    for node in nodes:
        node.stop()


@pytest.mark.parametrize("cluster", [{1: 1}, {1: 2}, {1: 2, 2: 2}])
def test_subscribe_to_invalid(comms_clients):
    client = comms_clients[1]
    # subscribe to unregistered address
    topic_id, _ = client.subscribe_to(generate_address())

    # FIXME: this should probably throw an exception rather than an empty result
    assert topic_id is ""
