import pytest

from raiden.tests.integration.network.transport.rif_comms.node import Node as CommsNode, Config as CommsConfig
from transport.rif_comms.utils import notification_to_payload


@pytest.fixture()
@pytest.mark.parametrize("amount_of_nodes")
def comms_nodes(amount_of_nodes) -> {int, CommsNode}:
    nodes = {}

    # setup
    for i in range(1, amount_of_nodes + 1):
        node = CommsNode(CommsConfig(i))
        nodes[i] = node

    yield nodes

    # teardown
    for node in nodes.values():
        node.stop()


@pytest.mark.parametrize("amount_of_nodes", [1])
def test_is_subscribed_to_self(comms_nodes):
    comms_node = comms_nodes[1]
    client, address = comms_node.client, comms_node.address

    # no subscription should be present
    assert client.is_subscribed_to(address) is False

    client.subscribe_to(address)

    # subscribe to self and check subscription
    assert client.is_subscribed_to(address) is True


@pytest.mark.parametrize("amount_of_nodes", [2])
def test_is_subscribed_to_peers(comms_nodes):
    comms_node_1, comms_node_2 = comms_nodes[1], comms_nodes[2]
    client_1, address_1 = comms_node_1.client, comms_node_1.address
    client_2, address_2 = comms_node_2.client, comms_node_2.address

    # no subscriptions should be present
    assert client_1.is_subscribed_to(address_1) is False
    assert client_1.is_subscribed_to(address_2) is False
    assert client_2.is_subscribed_to(address_1) is False
    assert client_2.is_subscribed_to(address_2) is False

    # subscribe from node 1 to 2
    client_1.subscribe_to(address_2)

    # check subscriptions
    assert client_1.is_subscribed_to(address_1) is False
    assert client_1.is_subscribed_to(address_2) is True
    assert client_2.is_subscribed_to(address_1) is False
    assert client_2.is_subscribed_to(address_2) is False

    # now from node 2 to 1 and check again
    client_2.subscribe_to(address_1)

    assert client_1.is_subscribed_to(address_1) is False
    assert client_1.is_subscribed_to(address_2) is True
    assert client_2.is_subscribed_to(address_1) is True
    assert client_2.is_subscribed_to(address_2) is False


@pytest.mark.parametrize("amount_of_nodes", [2])
def test_cross_messaging(comms_nodes):
    comms_node_1, comms_node_2 = comms_nodes[1], comms_nodes[2]
    client_1, address_1 = comms_node_1.client, comms_node_1.address
    client_2, address_2 = comms_node_2.client, comms_node_2.address

    # subscribe both nodes to each other
    _, sub_1_to_2 = client_1.subscribe_to(address_2)
    _, sub_2_to_1 = client_2.subscribe_to(address_1)

    payload_1 = "hello from 1"
    payload_2 = "hello from 2"

    client_1.send_message(payload_1, address_2)
    client_2.send_message(payload_2, address_1)

    for resp in sub_1_to_2:
        received_message = notification_to_payload(resp)
        assert received_message == payload_1
        break  # only 1 message is expected

    for resp in sub_2_to_1:
        received_message = notification_to_payload(resp)
        assert received_message == payload_2
        break  # only 1 message is expected
