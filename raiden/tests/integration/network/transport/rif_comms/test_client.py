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
@pytest.mark.xfail("underlying stub hasSubscriber method does not work properly")
def test_has_subscriber(comms_nodes):
    comms_node_1 = comms_nodes[1]
    client_1 = comms_node_1.client
    comms_node_2 = comms_nodes[2]
    client_2 = comms_node_2.client

    # FIXME: nodes shouldn't have to subscribe to themselves for this to work
    _, _ = client_1.subscribe_to(comms_node_1.address)
    _, _ = client_2.subscribe_to(comms_node_2.address)

    # subscribe from node 1 to 2
    _, _ = client_1.subscribe_to(comms_node_2.address)

    # check subscriptions
    assert client_1.is_subscribed_to(comms_node_1.address) is True
    # FIXME: have comms node hasSubscriber call work properly
    assert client_1.is_subscribed_to(comms_node_2.address) is True
    assert client_2.is_subscribed_to(comms_node_1.address) is False
    assert client_2.is_subscribed_to(comms_node_2.address) is True


@pytest.mark.parametrize("amount_of_nodes", [2])
@pytest.mark.xfail("underlying stub hasSubscriber method does not work properly")
def test_two_clients_cross_subscription(comms_nodes):
    comms_node_1 = comms_nodes[1]
    client_1 = comms_node_1.client
    comms_node_2 = comms_nodes[2]
    client_2 = comms_node_2.client

    # FIXME: nodes shouldn't have to subscribe to themselves for this to work
    _, _ = client_1.subscribe_to(comms_node_1.address)
    _, _ = client_2.subscribe_to(comms_node_2.address)

    # subscribe both nodes to each other
    _, _ = client_1.subscribe_to(comms_node_2.address)
    _, _ = client_2.subscribe_to(comms_node_1.address)

    # check subscriptions
    assert client_1.is_subscribed_to(comms_node_1.address) is True
    # FIXME: have comms node hasSubscriber call work properly
    assert client_1.is_subscribed_to(comms_node_2.address) is True
    # FIXME: have comms node hasSubscriber call work properly
    assert client_2.is_subscribed_to(comms_node_1.address) is True
    assert client_2.is_subscribed_to(comms_node_2.address) is True


@pytest.mark.skip(reason="hangs when attempting to sub to a node without it having subbed to itself first")
def test_two_clients_cross_messaging_same_topic(self):
    # register nodes 1 and 2
    notification_1 = self.client_1.connect()
    notification_2 = self.client_2.connect()

    # cross-subscribe both nodes
    _, one_sub_two = self.client_1.subscribe_to(self.address_2)
    _, two_sub_one = self.client_2.subscribe_to(self.address_1)

    payload_1 = "hello from 1"
    payload_2 = "hello from 2"

    self.client_1.send_message(payload_1, self.address_2)
    self.client_2.send_message(payload_2, self.address_1)

    for resp in one_sub_two:
        received_message = notification_to_payload(resp)
        assert received_message == payload_1
        break  # only 1 message is expected

    for resp in two_sub_one:
        received_message = notification_to_payload(resp)
        assert received_message == payload_2
        break  # only 1 message is expected
