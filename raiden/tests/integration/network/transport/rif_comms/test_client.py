import pytest

from raiden.tests.integration.network.transport.rif_comms.node import Node as CommsNode, Config as CommsConfig
from raiden.tests.integration.network.transport.utils import generate_address
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
def test_locate_own_peer_id(comms_nodes):
    comms_node = comms_nodes[1]

    # attempt to locate self
    assert comms_node.client._get_peer_id(comms_node.address) is not ""


# FIXME: causes ERR_NO_PEERS_IN_ROUTING_TABLE in comms node although it passes
@pytest.mark.parametrize("amount_of_nodes", [1])
def test_locate_unregistered_peer_id(comms_nodes):
    comms_node = comms_nodes[1]

    # attempt to locate an unregistered peer
    assert comms_node.client._get_peer_id(generate_address()) is ""


# FIXME: comms node prints strange ServerUnaryCall message
@pytest.mark.parametrize("amount_of_nodes", [1])
def test_has_subscriber_self(comms_nodes):
    comms_node = comms_nodes[1]
    client = comms_node.client
    address = comms_node.address
    client.subscribe_to(address)

    # subscribe to self and check subscription
    assert client.is_subscribed_to(address) is True


@pytest.mark.parametrize("amount_of_nodes", [2])
@pytest.mark.xfail(reason="underlying stub.hasSubscriber method does not work properly")
def test_has_subscriber(comms_nodes):
    comms_node_1 = comms_nodes[1]
    client_1 = comms_node_1.client
    comms_node_2 = comms_nodes[2]
    client_2 = comms_node_2.client

    # FIXME: nodes shouldn't have to subscribe to themselves for this to work
    client_1.subscribe_to(comms_node_1.address)
    client_2.subscribe_to(comms_node_2.address)

    # subscribe from node 1 to 2
    client_1.subscribe_to(comms_node_2.address)

    # check subscriptions
    assert client_1.is_subscribed_to(comms_node_1.address) is True
    # FIXME: have comms node hasSubscriber call work properly
    assert client_1.is_subscribed_to(comms_node_2.address) is True
    assert client_2.is_subscribed_to(comms_node_1.address) is False
    assert client_2.is_subscribed_to(comms_node_2.address) is True


@pytest.mark.parametrize("amount_of_nodes", [2])
@pytest.mark.xfail(reason="underlying stub.hasSubscriber method does not work properly")
def test_two_clients_cross_subscription(comms_nodes):
    comms_node_1 = comms_nodes[1]
    client_1 = comms_node_1.client
    comms_node_2 = comms_nodes[2]
    client_2 = comms_node_2.client

    # FIXME: nodes shouldn't have to subscribe to themselves for this to work
    client_1.subscribe_to(comms_node_1.address)
    client_2.subscribe_to(comms_node_2.address)

    # subscribe both nodes to each other
    client_1.subscribe_to(comms_node_2.address)
    client_2.subscribe_to(comms_node_1.address)

    # check subscriptions
    assert client_1.is_subscribed_to(comms_node_1.address) is True
    # FIXME: have comms node hasSubscriber call work properly
    assert client_1.is_subscribed_to(comms_node_2.address) is True
    # FIXME: have comms node hasSubscriber call work properly
    assert client_2.is_subscribed_to(comms_node_1.address) is True
    assert client_2.is_subscribed_to(comms_node_2.address) is True


@pytest.mark.parametrize("amount_of_nodes", [2])
def test_two_clients_cross_messaging_same_topic(comms_nodes):
    comms_node_1 = comms_nodes[1]
    client_1 = comms_node_1.client
    comms_node_2 = comms_nodes[2]
    client_2 = comms_node_2.client

    # FIXME: nodes shouldn't have to subscribe to themselves for this to work
    client_1.subscribe_to(comms_node_1.address)
    client_2.subscribe_to(comms_node_2.address)

    # subscribe both nodes to each other
    _, sub_1_to_2 = client_1.subscribe_to(comms_node_2.address)
    _, sub_2_to_1 = client_2.subscribe_to(comms_node_1.address)

    payload_1 = "hello from 1"
    payload_2 = "hello from 2"

    client_1.send_message(payload_1, comms_node_2.address)
    client_2.send_message(payload_2, comms_node_1.address)

    for resp in sub_1_to_2:
        received_message = notification_to_payload(resp)
        assert received_message == payload_1
        break  # only 1 message is expected

    for resp in sub_2_to_1:
        received_message = notification_to_payload(resp)
        assert received_message == payload_2
        break  # only 1 message is expected
