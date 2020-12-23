import pytest
from grpc._channel import _InactiveRpcError

from raiden.tests.integration.network.transport.rif_comms.node import Node as CommsNode, Config as CommsConfig
from raiden.tests.integration.network.transport.utils import generate_address
from transport.rif_comms.utils import notification_to_payload, get_sender_from_notification


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
    unregistered_address = generate_address()

    # no subscriptions should be present
    assert client._is_subscribed_to(unregistered_address) is False

    # subscribe to unregistered address
    topic_id, _ = client.subscribe_to(unregistered_address)

    # check subscription again
    # FIXME: this should probably throw an exception rather than an empty result
    assert topic_id is ""
    assert client._is_subscribed_to(unregistered_address) is False


@pytest.mark.parametrize("amount_of_nodes", [1])
def test_subscribe_to_self(comms_nodes):
    client, address = comms_nodes[1].client, comms_nodes[1].address

    # no subscription should be present
    assert client._is_subscribed_to(address) is False

    # subscribe to self and check subscription
    topic_id, _ = client.subscribe_to(address)
    assert topic_id
    assert client._is_subscribed_to(address) is True


@pytest.mark.parametrize("amount_of_nodes", [2])
def test_subscribe_to_peers(comms_nodes):
    comms_node_1, comms_node_2 = comms_nodes[1], comms_nodes[2]
    client_1, address_1 = comms_node_1.client, comms_node_1.address
    client_2, address_2 = comms_node_2.client, comms_node_2.address

    # no subscriptions should be present
    assert client_1._is_subscribed_to(address_2) is False
    assert client_2._is_subscribed_to(address_1) is False

    # subscribe from node 1 to 2 and check subscriptions
    topic_id_1, _ = client_1.subscribe_to(address_2)
    assert topic_id_1
    assert client_1._is_subscribed_to(address_1) is False
    assert client_1._is_subscribed_to(address_2) is True
    assert client_2._is_subscribed_to(address_1) is False
    assert client_2._is_subscribed_to(address_2) is False

    # subscribe from node 2 to 1 and check subscriptions
    topic_id_2, _ = client_2.subscribe_to(address_1)
    assert topic_id_2
    assert client_1._is_subscribed_to(address_1) is False
    assert client_1._is_subscribed_to(address_2) is True
    assert client_2._is_subscribed_to(address_1) is True
    assert client_2._is_subscribed_to(address_2) is False


@pytest.mark.parametrize("amount_of_nodes", [2])
def test_subscribe_to_repeated(comms_nodes):
    comms_node_1, comms_node_2 = comms_nodes[1], comms_nodes[2]
    client_1, address_1 = comms_node_1.client, comms_node_1.address
    client_2, address_2 = comms_node_2.client, comms_node_2.address

    # subscribe from node 1 to 2 and check subscription
    topic_id_1, _ = client_1.subscribe_to(address_2)
    assert topic_id_1
    assert client_1._is_subscribed_to(address_2) is True

    # subscribe again and check subscription
    topic_id_2, _ = client_1.subscribe_to(address_2)
    assert topic_id_2 == topic_id_1
    assert client_1._is_subscribed_to(address_2) is True


@pytest.mark.parametrize("amount_of_nodes", [1])
@pytest.mark.skip(reason="hangs, incomplete")
def test_send_message_invalid(comms_nodes):
    client, address = comms_nodes[1].client, comms_nodes[1].address

    # send message to unregistered peer
    # FIXME: hangs
    client.send_message("echo", generate_address())


@pytest.mark.parametrize("amount_of_nodes", [1])
def test_send_message_self(comms_nodes):
    client, address = comms_nodes[1].client, comms_nodes[1].address

    # subscribe to self, send and listen
    _, sub = client.subscribe_to(address)

    payload = "echo"
    client.send_message(payload, address)
    for resp in sub:
        received_message = notification_to_payload(resp)
        assert received_message == payload
        break  # only 1 message is expected


@pytest.mark.parametrize("amount_of_nodes", [2])
def test_send_message_peers(comms_nodes):
    comms_node_1, comms_node_2 = comms_nodes[1], comms_nodes[2]
    client_1, address_1 = comms_node_1.client, comms_node_1.address
    client_2, address_2 = comms_node_2.client, comms_node_2.address

    # listen on each node
    _, sub_1 = client_1.subscribe_to(address_1)
    _, sub_2 = client_2.subscribe_to(address_2)

    payload_1 = "hello from 1"
    payload_2 = "hello from 2"

    # send messages and listen
    client_1.send_message(payload_1, address_2)
    client_2.send_message(payload_2, address_1)

    for resp in sub_1:
        received_message = notification_to_payload(resp)
        assert received_message == payload_2
        break  # only 1 message is expected

    for resp in sub_2:
        received_message = notification_to_payload(resp)
        assert received_message == payload_1
        break  # only 1 message is expected


@pytest.mark.parametrize("amount_of_nodes", [2])
def test_send_message_sender(comms_nodes):
    comms_node_1, comms_node_2 = comms_nodes[1], comms_nodes[2]
    client_1, address_1 = comms_node_1.client, comms_node_1.address
    client_2, address_2 = comms_node_2.client, comms_node_2.address

    # listen on both nodes
    _, sub_1 = client_1.subscribe_to(address_1)
    _, sub_2 = client_2.subscribe_to(address_2)

    # send and receive messages
    client_1.send_message("ping", address_2)
    client_2.send_message("pong", address_1)

    for resp in sub_1:
        sender = get_sender_from_notification(resp)
        assert sender == address_2
        break  # only 1 message is expected

    for resp in sub_2:
        sender = get_sender_from_notification(resp)
        assert sender == address_1
        break  # only 1 message is expected


@pytest.mark.parametrize("amount_of_nodes", [2])
def test_send_message_subscription(comms_nodes):
    comms_node_1, comms_node_2 = comms_nodes[1], comms_nodes[2]
    client_1, address_1 = comms_node_1.client, comms_node_1.address
    client_2, address_2 = comms_node_2.client, comms_node_2.address

    # node 2 must listen to its own topic
    _, sub = client_2.subscribe_to(address_2)

    # send message and receive without subscription
    payload = "marco"
    client_1.send_message(payload, address_2)
    for resp in sub:
        received_message = notification_to_payload(resp)
        assert received_message == payload
        break  # only 1 message is expected

    # now subscribe from node 1 to 2
    client_1.subscribe_to(address_2)

    # message should be successfully sent and received again
    payload = "polo"
    client_1.send_message(payload, address_2)
    for resp in sub:
        received_message = notification_to_payload(resp)
        assert received_message == payload
        break  # only 1 message is expected


@pytest.mark.parametrize("amount_of_nodes", [1])
@pytest.mark.xfail(reason="unexpected behavior from comms")
def test_unsubscribe_from_invalid(comms_nodes):
    client, address = comms_nodes[1].client, comms_nodes[1].address

    # unsubscribe from non-subscribed address
    with pytest.raises(_InactiveRpcError) as e:
        client.unsubscribe_from(address)

    assert "not subscribed to" in str.lower(e.value.details())

    # unsubscribe from unregistered address
    with pytest.raises(_InactiveRpcError) as e:
        client.unsubscribe_from(generate_address())

    assert "not subscribed to" in str.lower(e.value.details())


@pytest.mark.parametrize("amount_of_nodes", [1])
def test_unsubscribe_from_self(comms_nodes):
    client, address = comms_nodes[1].client, comms_nodes[1].address

    # subscribe to self, then unsubscribe from self
    client.subscribe_to(address)
    client.unsubscribe_from(address)

    assert client._is_subscribed_to(address) is False


@pytest.mark.parametrize("amount_of_nodes", [2])
def test_unsubscribe_from_peers(comms_nodes):
    comms_node_1, comms_node_2 = comms_nodes[1], comms_nodes[2]
    client_1, address_1 = comms_node_1.client, comms_node_1.address
    client_2, address_2 = comms_node_2.client, comms_node_2.address

    # subscribe both nodes to each other
    client_1.subscribe_to(address_2)
    client_2.subscribe_to(address_1)

    # unsubscribe both nodes from each other
    client_1.unsubscribe_from(address_2)
    assert client_1._is_subscribed_to(address_2) is False
    assert client_2._is_subscribed_to(address_1) is True  # check operations are independent
    client_2.unsubscribe_from(address_1)
    assert client_2._is_subscribed_to(address_1) is False
    assert client_1._is_subscribed_to(address_2) is False  # check operations are independent
