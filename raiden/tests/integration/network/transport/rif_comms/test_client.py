import pytest
from grpc._channel import _InactiveRpcError

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
def test_subscribe_to_invalid(comms_nodes):
    client = comms_nodes[1].client

    invalid_addr = generate_address()
    topic_id, _ = client.subscribe_to(invalid_addr)

    # FIXME: this should probably throw an exception rather than an empty result
    assert topic_id is ""


@pytest.mark.parametrize("amount_of_nodes", [1])
def test_subscribe_to_self(comms_nodes):
    client, address = comms_nodes[1].client, comms_nodes[1].address

    topic_id, _ = client.subscribe_to(address)

    assert topic_id


@pytest.mark.parametrize("amount_of_nodes", [2])
def test_subscribe_to_peers(comms_nodes):
    comms_node_1, comms_node_2 = comms_nodes[1], comms_nodes[2]
    client_1, address_1 = comms_node_1.client, comms_node_1.address
    client_2, address_2 = comms_node_2.client, comms_node_2.address

    topic_id_1, _ = client_1.subscribe_to(address_2)

    assert topic_id_1

    topic_id_2, _ = client_2.subscribe_to(address_1)

    assert topic_id_2


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


@pytest.mark.parametrize("amount_of_nodes", [1])
@pytest.mark.skip(reason="hangs, incomplete")
def test_send_message_invalid_address(comms_nodes):
    client, address = comms_nodes[1].client, comms_nodes[1].address

    # send message to unregistered peer
    # FIXME: hangs
    client.send_message("echo", generate_address())


@pytest.mark.parametrize("amount_of_nodes", [2])
def test_send_message_with_subscription(comms_nodes):
    comms_node_1, comms_node_2 = comms_nodes[1], comms_nodes[2]
    client_1, address_1 = comms_node_1.client, comms_node_1.address
    client_2, address_2 = comms_node_2.client, comms_node_2.address

    # node 2 must listen to its own topic
    _, sub = client_2.subscribe_to(address_2)

    with pytest.raises(_InactiveRpcError) as e:
        client_1.send_message("marco", address_2)
        assert "Not subscribed to" in e.details()

    # subscribe from node 1 to 2
    client_1.subscribe_to(address_2)

    # message should be successfully sent now
    client_1.send_message("polo", address_2)
    for resp in sub:
        received_message = notification_to_payload(resp)
        assert received_message == "polo"
        break  # only 1 message is expected


@pytest.mark.parametrize("amount_of_nodes", [2])
def test_send_message_peers(comms_nodes):
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
