from typing import List, Dict

import pytest
from eth_utils import to_canonical_address
from grpc._channel import _InactiveRpcError

from raiden.tests.integration.network.transport.rif_comms.node import Node as CommsNode, Config as CommsConfig
from raiden.tests.integration.network.transport.utils import generate_address
from transport.rif_comms.client import Client
from transport.rif_comms.cluster import Cluster
from transport.rif_comms.utils import notification_to_payload, get_sender_from_notification


@pytest.fixture()
@pytest.mark.parametrize("nodes_to_clients")
def comms_clients(nodes_to_clients: dict) -> Dict[int, Client]:
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

    cluster = Cluster(nodes_to_clients)
    yield cluster.get_clients()

    # teardown
    cluster.shutdown()


@pytest.mark.xfail(reason="wrong exception message from comms node")
def test_connect():
    # the comms_nodes fixture is not used to prevent automatic connect
    nodes = []
    try:
        node = CommsNode(CommsConfig(node_number=1, amount_of_clients=1, auto_connect=False))
        nodes.append(node)
        client, address = node.clients[0], node.clients[0].rsk_address.address

        # no peer ID should be registered under this address yet
        with pytest.raises(_InactiveRpcError) as e:
            client._get_peer_id(address)

        assert "not found" in str.lower(e.value.details())

        # connect and check again
        client.connect()
        assert client._get_peer_id(address)
    finally:
        for node in nodes:
            node.stop()


def test_connect_repeated():
    # the comms_nodes fixture is not used to prevent automatic connect
    nodes = []
    try:
        node = CommsNode(CommsConfig(node_number=1, amount_of_clients=1, auto_connect=False))
        nodes.append(node)
        client, address = node.clients[0], node.clients[0].rsk_address.address

        client.connect()
        peer_id_1 = client._get_peer_id(address)

        # repeat connection and check peer id
        client.connect()
        peer_id_2 = client._get_peer_id(address)
        assert peer_id_2 == peer_id_1
    finally:
        for node in nodes:
            node.stop()


def test_connect_peers():
    # the comms_nodes fixture is not used to prevent automatic connect
    nodes = []
    try:
        node_1 = CommsNode(CommsConfig(node_number=1, amount_of_clients=1, auto_connect=False))
        nodes.append(node_1)
        client_1, address_1 = node_1.clients[0], node_1.clients[0].rsk_address.address

        node_2 = CommsNode(CommsConfig(node_number=2, amount_of_clients=1, auto_connect=False))
        nodes.append(node_2)
        client_2, address_2 = node_2.clients[0], node_2.clients[0].rsk_address.address

        # connect clients
        client_1.connect()
        client_2.connect()

        # check from peers that connections were successfully made
        assert client_1._get_peer_id(address_2)
        assert client_2._get_peer_id(address_1)
    finally:
        for node in nodes:
            node.stop()


def test_send_message_shutdown():
    # the comms_nodes fixture is not used in order to shut down nodes manually
    nodes = []
    try:
        node_1 = CommsNode(CommsConfig(node_number=1, amount_of_clients=1, auto_connect=False))
        nodes.append(node_1)
        client_1, address_1 = node_1.clients[0], node_1.clients[0].rsk_address.address

        node_2 = CommsNode(CommsConfig(node_number=2, amount_of_clients=1, auto_connect=False))
        nodes.append(node_2)
        client_2, address_2 = node_2.clients[0], node_2.clients[0].rsk_address.address

        # connect clients
        client_1.connect()
        client_2.connect()

        # shut down node 2
        node_2.stop()

        # send message
        client_1.send_message("into the void", address_2)  # no exception should be raised
    finally:
        for node in nodes:
            # because node 2 can be already stopped, we cannot call stop() indiscriminately
            if not node._process.poll():  # if True, node is still running
                node.stop()


@pytest.mark.parametrize("nodes_to_clients", [{1: 1}, {1: 2}])
def test_subscribe_to_invalid(comms_clients):
    unregistered_address = generate_address()
    for client in comms_clients.values():
        # no subscriptions should be present
        assert client._is_subscribed_to(unregistered_address) is False
        # subscribe to unregistered address
        topic_id, _ = client.subscribe_to(unregistered_address)
        # FIXME: this should probably throw an exception rather than an empty result
        assert topic_id is ""
        assert client._is_subscribed_to(unregistered_address) is False


@pytest.mark.parametrize("nodes_to_clients", [{1: 1}, {1: 2}, {1: 2, 2: 2}])
def test_subscribe_to_self(comms_clients):
    for client in comms_clients.values():
        # no subscription should be present
        assert client._is_subscribed_to(client.rsk_address.address) is False
        # subscribe to self and check subscription
        topic_id, _ = client.subscribe_to(client.rsk_address.address)
        assert topic_id
        assert client._is_subscribed_to(client.rsk_address.address) is True


@pytest.mark.xfail(reason="fails, multi addr issue")
@pytest.mark.parametrize("nodes_to_clients", [{1: 1, 2: 1}, {1: 2}])
def test_subscribe_to_peers(comms_clients):
    client_1 = comms_clients[1]
    client_2 = comms_clients[2]

    # no subscriptions should be present
    assert client_1._is_subscribed_to(client_2.rsk_address.address) is False
    assert client_2._is_subscribed_to(client_1.rsk_address.address) is False

    # subscribe from node 1 to 2 and check subscriptions
    topic_id_1, _ = client_1.subscribe_to(client_2.rsk_address.address)
    assert topic_id_1
    assert client_1._is_subscribed_to(client_1.rsk_address.address) is False
    assert client_1._is_subscribed_to(client_2.rsk_address.address) is True
    assert client_2._is_subscribed_to(client_1.rsk_address.address) is False
    assert client_2._is_subscribed_to(client_2.rsk_address.address) is False # FIXME this fails

    topic_id_2, _ = client_2.subscribe_to(client_1.rsk_address.address)
    assert topic_id_2
    assert client_1._is_subscribed_to(client_1.rsk_address.address) is False
    assert client_1._is_subscribed_to(client_2.rsk_address.address) is True
    assert client_2._is_subscribed_to(client_1.rsk_address.address) is True
    assert client_2._is_subscribed_to(client_2.rsk_address.address) is False


@pytest.mark.parametrize("nodes_to_clients", [{1: 1, 2: 1}, {1: 2}])
def test_subscribe_to_repeated(comms_clients):
    client_1 = comms_clients[1]
    client_2 = comms_clients[2]

    # subscribe from node 1 to 2 and check subscription
    topic_id_1, _ = client_1.subscribe_to(client_2.rsk_address.address)
    assert topic_id_1
    assert client_1._is_subscribed_to(client_2.rsk_address.address) is True

    # subscribe again and check subscription
    topic_id_2, _ = client_1.subscribe_to(client_2.rsk_address.address)
    assert topic_id_1 == topic_id_2
    assert client_1._is_subscribed_to(client_2.rsk_address.address) is True


@pytest.mark.xfail(reason="fails, last assertion fails, multi addr issue")
@pytest.mark.parametrize("nodes_to_clients", [{1: 1, 2: 1}, {1: 2}])
def test_is_subscribed_to_self_mutli_address(comms_clients):
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


@pytest.mark.parametrize("nodes_to_clients", [{1: 1}])
@pytest.mark.skip(reason="hangs, incomplete")
def test_send_message_invalid(comms_clients):
    client = comms_clients[1]
    # send message to unregistered peer
    # FIXME: hangs
    client.send_message("echo", generate_address())


@pytest.mark.parametrize("nodes_to_clients", [{1: 1, 2: 1}, {1: 2}])
def test_send_message_subscription(comms_clients):
    client_1 = comms_clients[1]
    client_2 = comms_clients[2]

    # node 2 must listen to its own topic
    _, sub = client_2.subscribe_to(client_2.rsk_address.address)

    # message should be successfully sent, no subscription needed
    payload = "marco"
    client_1.send_message(payload, client_2.rsk_address.address)
    for resp in sub:
        received_message = notification_to_payload(resp)
        assert received_message == payload
        break  # only 1 message is expected

    # send message with subscription
    client_1.subscribe_to(client_2.rsk_address.address)
    payload = "polo"
    client_1.send_message(payload, client_2.rsk_address.address)
    for resp in sub:
        received_message = notification_to_payload(resp)
        assert received_message == payload
        break  # only 1 message is expected


@pytest.mark.parametrize("nodes_to_clients", [{1: 1}])
def test_send_message_self(comms_clients):
    client = comms_clients[1]

    # subscribe to self, send and listen
    _, sub = client.subscribe_to(client.rsk_address.address)

    payload = "echo"
    client.send_message(payload, client.rsk_address.address)
    for resp in sub:
        received_message = notification_to_payload(resp)
        assert received_message == payload
        break  # only 1 message is expected


@pytest.mark.parametrize("nodes_to_clients", [{1: 1, 2: 1}, {1: 2}])
def test_send_message_peers(comms_clients):
    client_1 = comms_clients[1]
    client_2 = comms_clients[2]

    # subscribe both nodes to self to start listening
    _, sub_1_ = client_1.subscribe_to(client_1.rsk_address.address)
    _, sub_2 = client_2.subscribe_to(client_2.rsk_address.address)

    payload_1 = "hello from 1"
    payload_2 = "hello from 2"

    # send messages
    client_1.send_message(payload_1, client_2.rsk_address.address)
    client_2.send_message(payload_2, client_1.rsk_address.address)

    for resp in sub_1_:
        received_message = notification_to_payload(resp)
        assert received_message == payload_2
        break  # only 1 message is expected

    for resp in sub_2:
        received_message = notification_to_payload(resp)
        assert received_message == payload_1
        break  # only 1 message is expected


@pytest.mark.parametrize("nodes_to_clients", [{1: 1}])
@pytest.mark.xfail(reason="exceptions are not raised from comms node")
def test_unsubscribe_from_invalid(comms_clients):
    client = comms_clients[1]

    # unsubscribe from non-subscribed address
    with pytest.raises(_InactiveRpcError) as e:
        client.unsubscribe_from(client.rsk_address.address)

    assert "not subscribed to" in str.lower(e.value.details())

    # unsubscribe from unregistered address
    with pytest.raises(_InactiveRpcError) as e:
        client.unsubscribe_from(generate_address())

    assert "not subscribed to" in str.lower(e.value.details())


@pytest.mark.parametrize("nodes_to_clients", [{1: 1, 2: 1}, {1: 2}])
@pytest.mark.xfail(reason="wrong rif comms subscription behaviour cluster 2")
def test_unsubscribe_from_self(comms_clients):
    client_1 = comms_clients[1]
    client_2 = comms_clients[2]

    # subscribe to self, then unsubscribe from self
    client_1.subscribe_to(client_1.rsk_address.address)
    assert client_1._is_subscribed_to(client_1.rsk_address.address) is True
    assert client_1._is_subscribed_to(client_2.rsk_address.address) is False

    client_2.subscribe_to(client_2.rsk_address.address)
    assert client_2._is_subscribed_to(client_2.rsk_address.address) is True
    assert client_2._is_subscribed_to(client_1.rsk_address.address) is False  # FIXME this fails scenario cluster 2

    client_1.unsubscribe_from(client_1.rsk_address.address)
    assert client_1._is_subscribed_to(client_1.rsk_address.address) is False
    assert client_2._is_subscribed_to(client_2.rsk_address.address) is True

    client_2.unsubscribe_from(client_2.rsk_address.address)
    assert client_2._is_subscribed_to(client_2.rsk_address.address) is False


@pytest.mark.parametrize("nodes_to_clients", [{1: 1, 2: 1}, {1: 2}])
def test_unsubscribe_from_peers(comms_clients):
    client_1 = comms_clients[1]
    client_2 = comms_clients[2]

    # subscribe both nodes to each other
    client_1.subscribe_to(client_2.rsk_address.address)
    client_2.subscribe_to(client_1.rsk_address.address)

    # unsubscribe both nodes from each other
    client_1.unsubscribe_from(client_2.rsk_address.address)
    assert client_1._is_subscribed_to(client_2.rsk_address.address) is False
    assert client_2._is_subscribed_to(client_1.rsk_address.address) is True  # check operations are independent
    client_2.unsubscribe_from(client_1.rsk_address.address)
    assert client_2._is_subscribed_to(client_1.rsk_address.address) is False
    assert client_1._is_subscribed_to(client_2.rsk_address.address) is False  # check operations are independent


@pytest.mark.parametrize("nodes_to_clients", [{1: 1, 2: 1}, {1: 2}])
def test_send_message_sender(comms_clients):
    client_1 = comms_clients[1]
    client_2 = comms_clients[2]

    # subscribe both nodes to each other
    _, sub_1 = client_1.subscribe_to(client_1.rsk_address.address)
    _, sub_2 = client_2.subscribe_to(client_2.rsk_address.address)

    # send messages and listen
    client_1.send_message("ping", client_2.rsk_address.address)
    client_2.send_message("pong", client_1.rsk_address.address)

    for resp in sub_1:
        sender = get_sender_from_notification(resp)
        assert sender == to_canonical_address(client_2.rsk_address.address)
        break  # only 1 message is expected

    for resp in sub_2:
        sender = get_sender_from_notification(resp)
        assert sender == to_canonical_address(client_1.rsk_address.address)
        break  # only 1 message is expected
