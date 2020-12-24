from typing import List, Dict

import pytest

from raiden.tests.integration.network.transport.rif_comms.node import Node as CommsNode, Config as CommsConfig
from raiden.tests.integration.network.transport.utils import generate_address
from transport.rif_comms.client import Client


@pytest.fixture()
@pytest.mark.parametrize("cluster")
def comms_clients(cluster: dict) -> Dict[int, Client]:
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
    for client in comms_clients.values():
        # subscribe to unregistered address
        topic_id, _ = client.subscribe_to(generate_address())
        # FIXME: this should probably throw an exception rather than an empty result
        assert topic_id is ""


@pytest.mark.parametrize("cluster", [{1: 1}, {1: 2}, {1: 2, 2: 2}])
def test_subscribe_to_self(comms_clients):
    for client in comms_clients.values():
        topic_id, _ = client.subscribe_to(client.rsk_address.address)
        assert topic_id


@pytest.mark.parametrize("cluster", [{1: 1, 2: 1}, {1: 2}])
def test_subscribe_to_peers(comms_clients):
    client_1 = comms_clients[1]
    client_2 = comms_clients[2]

    topic_id_1, _ = client_1.subscribe_to(client_2.rsk_address.address)
    assert topic_id_1
    topic_id_2, _ = client_2.subscribe_to(client_1.rsk_address.address)
    assert topic_id_2


@pytest.mark.parametrize("cluster", [{1: 1, 2: 1}, {1: 2}])
def test_subscribe_to_repeated(comms_clients):
    client_1 = comms_clients[1]
    client_2 = comms_clients[2]

    topic_id_1, _ = client_1.subscribe_to(client_2.rsk_address.address)
    topic_id_2, _ = client_1.subscribe_to(client_2.rsk_address.address)

    assert topic_id_1 == topic_id_2


@pytest.mark.parametrize("cluster", [{1: 1, 2: 1}, {1: 2}])
def test_is_subscribed_to_invalid(comms_clients):
    client_1 = comms_clients[1]
    client_2 = comms_clients[2]
    # check subscription to non-subscribed address
    assert client_1._is_subscribed_to(client_1.rsk_address.address) is False
    assert client_2._is_subscribed_to(client_2.rsk_address.address) is False
    # check subscription to unregistered address
    assert client_1._is_subscribed_to(generate_address()) is False
    assert client_2._is_subscribed_to(generate_address()) is False


@pytest.mark.xfail(reason="fails, last assertion fails, multi addr issue")
@pytest.mark.parametrize("cluster", [{1: 1, 2: 1}, {1: 2}])
def test_is_subscribed_to_self(comms_clients):
    client_1 = comms_clients[1]
    client_2 = comms_clients[2]

    # no subscription should be present
    assert client_1._is_subscribed_to(client_1.rsk_address.address) is False
    assert client_2._is_subscribed_to(client_2.rsk_address.address) is False

    # subscribe to self and check subscription
    client_1.subscribe_to(client_1.rsk_address.address)
    client_2.subscribe_to(client_2.rsk_address.address)

    assert client_1._is_subscribed_to(client_1.rsk_address.address) is True
    assert client_2._is_subscribed_to(client_2.rsk_address.address) is True

    # should not be subscribed to each other, even if they share comms node
    assert client_2._is_subscribed_to(client_1.rsk_address.address) is False
    assert client_1._is_subscribed_to(client_2.rsk_address.address) is False  # FIXME this fails


@pytest.mark.xfail(reason="fails, last assertion fails, multi addr issue")
@pytest.mark.parametrize("cluster", [{1: 1, 2: 1}, {1: 2}])
def test_is_subscribed_to_peers(comms_clients):
    client_1 = comms_clients[1]
    client_2 = comms_clients[2]

    # no subscriptions should be present
    assert client_1._is_subscribed_to(client_1.rsk_address.address) is False
    assert client_1._is_subscribed_to(client_2.rsk_address.address) is False
    assert client_2._is_subscribed_to(client_1.rsk_address.address) is False
    assert client_2._is_subscribed_to(client_2.rsk_address.address) is False

    # subscribe from node 1 to 2
    client_1.subscribe_to(client_2.rsk_address.address)

    # check subscriptions
    assert client_1._is_subscribed_to(client_1.rsk_address.address) is False
    assert client_1._is_subscribed_to(client_2.rsk_address.address) is True
    assert client_2._is_subscribed_to(client_1.rsk_address.address) is False
    assert client_2._is_subscribed_to(client_2.rsk_address.address) is False # FIXME this fails

    # now from node 2 to 1 and check again
    client_2.subscribe_to(client_1.rsk_address.address)

    assert client_1._is_subscribed_to(client_1.rsk_address.address) is False
    assert client_1._is_subscribed_to(client_2.rsk_address.address) is True
    assert client_2._is_subscribed_to(client_1.rsk_address.address) is True
    assert client_2._is_subscribed_to(client_2.rsk_address.address) is False
