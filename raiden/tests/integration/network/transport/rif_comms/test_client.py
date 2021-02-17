from typing import Dict, Callable, Union

import pytest
from eth_utils import to_canonical_address, to_checksum_address
from grpc import RpcError, StatusCode

from raiden.tests.integration.network.transport.rif_comms.cluster import Cluster
from raiden.tests.integration.network.transport.rif_comms.node import Node as CommsNode, Config as CommsConfig
from raiden.tests.integration.network.transport.utils import generate_address
from raiden.utils import Address
from transport.rif_comms.client import Client
from transport.rif_comms.client_exception_handler import ClientExceptionHandler
from transport.rif_comms.exceptions import NotFoundException, FailedPreconditionException, InvalidArgumentException, \
    TimeoutException, ClientException
from transport.rif_comms.proto.api_pb2 import RskAddressPublish, Msg, RskSubscription, RskAddress
from transport.rif_comms.utils import notification_to_payload, get_sender_from_notification


@pytest.fixture()
@pytest.mark.parametrize("nodes_to_clients")
def comms_clients(nodes_to_clients: dict) -> Dict[int, Client]:
    cluster = Cluster(nodes_to_clients)
    yield cluster.get_clients()

    # teardown
    cluster.stop()


def test_connect_failure():
    # the comms_nodes fixture is not used to prevent automatic connect
    nodes = []
    try:
        node = CommsNode(CommsConfig(node_id="A", amount_of_clients=1, auto_connect=False))
        nodes.append(node)
        client = node.clients[0]

        # bypass client.connect to provide invalid address
        invalid_address = RskAddress(address="invalid")
        expect_error(
            expected_exception=RpcError,
            expected_mapped_type=InvalidArgumentException,
            expected_code=StatusCode.INVALID_ARGUMENT,
            expected_message=f"{invalid_address.address} is not a valid RSK address",
            call=client.stub.ConnectToCommunicationsNode,
            request=invalid_address,
            timeout=client.grpc_client_timeout,
        )
    finally:
        for node in nodes:
            node.stop()


def test_connect():
    # the comms_nodes fixture is not used to prevent automatic connect
    nodes = []
    try:
        node = CommsNode(CommsConfig(node_id="A", amount_of_clients=1, auto_connect=False))
        nodes.append(node)
        client, address = node.clients[0], node.clients[0].rsk_address.address

        # no peer ID should be registered under this address yet
        expect_error(
            expected_exception=NotFoundException,
            expected_mapped_type=None,
            expected_code=StatusCode.NOT_FOUND,
            expected_message=f"Rsk address {to_checksum_address(address)} not registered",
            call=client._get_peer_id,
            rsk_address=address,
        )

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
        node = CommsNode(CommsConfig(node_id="A", amount_of_clients=1, auto_connect=False))
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
        node_1 = CommsNode(CommsConfig(node_id="A", amount_of_clients=1, auto_connect=False))
        nodes.append(node_1)
        client_1, address_1 = node_1.clients[0], node_1.clients[0].rsk_address.address

        node_2 = CommsNode(CommsConfig(node_id="B", amount_of_clients=1, auto_connect=False))
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


@pytest.mark.parametrize("nodes_to_clients", [{"A": 1}, {"A": 2}])
def test_subscribe_to_unregistered_address(comms_clients):
    unregistered_address = generate_address()

    for client in comms_clients.values():
        expected_error = f"Rsk address {to_checksum_address(unregistered_address)} not registered"

        # attempt to check subscription to unregistered address
        expect_error(
            expected_exception=NotFoundException,
            expected_mapped_type=None,
            expected_code=StatusCode.NOT_FOUND,
            expected_message=expected_error,
            call=client._is_subscribed_to,
            rsk_address=unregistered_address,
        )

        # attempt to subscribe to unregistered address
        expect_error(
            expected_exception=NotFoundException,
            expected_mapped_type=None,
            expected_code=StatusCode.NOT_FOUND,
            expected_message=expected_error,
            call=client.subscribe_to,
            rsk_address=unregistered_address,
        )


@pytest.mark.parametrize("nodes_to_clients", [{"A": 1}, {"A": 2}])
def test_subscribe_to_invalid_address(comms_clients):
    invalid_address = RskAddress(address=Address("0x123"))
    invalid_address_message = f"{invalid_address.address} is not a valid RSK address"

    for client in comms_clients.values():
        # bypass client.subscribe_to to provide invalid address as topic
        def subscribe_to_invalid_topic():
            topic = client.stub.CreateTopicWithRskAddress(
                RskSubscription(
                    topic=invalid_address,
                    subscriber=client.rsk_address
                ),
                timeout=client.grpc_client_timeout,
            )
            for _ in topic:
                pytest.fail("exception should be raised before reaching this point")

        expect_error(
            expected_exception=RpcError,
            expected_mapped_type=InvalidArgumentException,
            expected_code=StatusCode.INVALID_ARGUMENT,
            expected_message=invalid_address_message,
            call=subscribe_to_invalid_topic,
        )

        # bypass client.subscribe_to to provide invalid address as subscriber
        def subscribe_to_invalid_subscriber():
            topic = client.stub.CreateTopicWithRskAddress(
                RskSubscription(
                    topic=client.rsk_address,
                    subscriber=invalid_address,
                ),
                timeout=client.grpc_client_timeout,
            )
            for _ in topic:
                pytest.fail("exception should be raised before reaching this point")

        expect_error(
            expected_exception=RpcError,
            expected_mapped_type=InvalidArgumentException,
            expected_code=StatusCode.INVALID_ARGUMENT,
            expected_message=invalid_address_message,
            call=subscribe_to_invalid_subscriber,
        )


@pytest.mark.parametrize("nodes_to_clients", [{"A": 1, "B": 1}, {"A": 2}])
def test_subscribe_to_self(comms_clients):
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
    assert client_1._is_subscribed_to(client_2.rsk_address.address) is False


@pytest.mark.parametrize("nodes_to_clients", [{"A": 1, "B": 1}, {"A": 2}])
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
    assert client_2._is_subscribed_to(client_2.rsk_address.address) is False

    # subscribe from node 2 to 1 and check subscriptions
    topic_id_2, _ = client_2.subscribe_to(client_1.rsk_address.address)
    assert topic_id_2
    assert client_1._is_subscribed_to(client_1.rsk_address.address) is False
    assert client_1._is_subscribed_to(client_2.rsk_address.address) is True
    assert client_2._is_subscribed_to(client_1.rsk_address.address) is True
    assert client_2._is_subscribed_to(client_2.rsk_address.address) is False


@pytest.mark.parametrize("nodes_to_clients", [{"A": 1, "B": 1}, {"A": 2}])
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


@pytest.mark.parametrize("nodes_to_clients", [{"A": 1}])
def test_send_message_unregistered_address(comms_clients):
    client = comms_clients[1]

    # attempt to send message to unregistered address
    unregistered_address = generate_address()
    expect_error(
        expected_exception=NotFoundException,
        expected_mapped_type=None,
        expected_code=StatusCode.NOT_FOUND,
        expected_message=f"Rsk address {to_checksum_address(unregistered_address)} not registered",
        call=client.send_message,
        payload="echo",
        rsk_address=unregistered_address,
    )


@pytest.mark.parametrize("nodes_to_clients", [{"A": 1}])
def test_send_message_invalid_address(comms_clients):
    client = comms_clients[1]

    # attempt to send message using an invalid address
    invalid_address = RskAddress(address="0x123")
    invalid_address_message = f"{invalid_address.address} is not a valid RSK address"

    # bypass client.send_message to provide an invalid address as receiver
    expect_error(
        expected_exception=RpcError,
        expected_mapped_type=InvalidArgumentException,
        expected_code=StatusCode.INVALID_ARGUMENT,
        expected_message=invalid_address_message,
        call=client.stub.SendMessageToRskAddress,
        request=RskAddressPublish(sender=client.rsk_address, receiver=invalid_address,
                                  message=Msg(payload=str.encode("echo"))),
        timeout=client.grpc_client_timeout,
    )

    # bypass client.send_message to provide an invalid address as sender
    expect_error(
        expected_exception=RpcError,
        expected_mapped_type=InvalidArgumentException,
        expected_code=StatusCode.INVALID_ARGUMENT,
        expected_message=invalid_address_message,
        call=client.stub.SendMessageToRskAddress,
        request=RskAddressPublish(sender=invalid_address, receiver=client.rsk_address,
                                  message=Msg(payload=str.encode("echo"))),
        timeout=client.grpc_client_timeout,
    )


@pytest.mark.parametrize("nodes_to_clients", [{"A": 1}])
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


@pytest.mark.parametrize("nodes_to_clients", [{"A": 1, "B": 1}, {"A": 2}])
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


@pytest.mark.parametrize("nodes_to_clients", [{"A": 1, "B": 1}, {"A": 2}])
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


@pytest.mark.parametrize("nodes_to_clients", [{"A": 1, "B": 1}, {"A": 2}])
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


def test_send_message_shutdown():
    # the comms_nodes fixture is not used in order to shut down nodes manually
    nodes = []
    try:
        node_1 = CommsNode(CommsConfig(node_id="A", amount_of_clients=1, auto_connect=False))
        nodes.append(node_1)
        client_1, address_1 = node_1.clients[0], node_1.clients[0].rsk_address.address

        node_2 = CommsNode(CommsConfig(node_id="B", amount_of_clients=1, auto_connect=False))
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


@pytest.mark.parametrize("nodes_to_clients", [{"A": 1}])
def test_unsubscribe_from_non_subscribed_address(comms_clients):
    client = comms_clients[1]

    address = client.rsk_address.address
    # attempt to unsubscribe from non-subscribed address
    expect_error(
        expected_exception=FailedPreconditionException,
        expected_mapped_type=None,
        expected_code=StatusCode.FAILED_PRECONDITION,
        expected_message=f"not subscribed to {to_checksum_address(address)}",
        call=client.unsubscribe_from,
        rsk_address=address,
    )

    address = generate_address()
    # attempt to unsubscribe from unregistered address
    expect_error(
        expected_exception=NotFoundException,
        expected_mapped_type=None,
        expected_code=StatusCode.NOT_FOUND,
        expected_message=f"Rsk address {to_checksum_address(address)} not registered",
        call=client.unsubscribe_from,
        rsk_address=address,
    )


@pytest.mark.parametrize("nodes_to_clients", [{"A": 1}])
@pytest.mark.xfail(reason="wrong error code/msg from comms")
def test_unsubscribe_from_invalid_address(comms_clients):
    client = comms_clients[1]

    # attempt to unsubscribe using an invalid address
    invalid_address = RskAddress(address="0xfoobar")
    invalid_address_message = f"{invalid_address.address} is not a valid RSK address"

    # bypass client.unsubscribe_from to provide an invalid address as topic
    expect_error(
        expected_exception=RpcError,
        expected_mapped_type=InvalidArgumentException,
        expected_code=StatusCode.INVALID_ARGUMENT,
        expected_message=invalid_address_message,
        call=client.stub.CloseTopicWithRskAddress,
        request=RskSubscription(topic=invalid_address, subscriber=client.rsk_address),
        timeout=client.grpc_client_timeout,
    )

    # bypass client.unsubscribe_from to provide an invalid address as subscriber
    expect_error(
        expected_exception=RpcError,
        expected_mapped_type=InvalidArgumentException,
        expected_code=StatusCode.INVALID_ARGUMENT,
        expected_message=invalid_address_message,
        call=client.stub.CloseTopicWithRskAddress,
        request=RskSubscription(topic=client.rsk_address, subscriber=invalid_address),
        timeout=client.grpc_client_timeout,
    )


@pytest.mark.parametrize("nodes_to_clients", [{"A": 1, "B": 1}, {"A": 2}])
def test_unsubscribe_from_self(comms_clients):
    client_1 = comms_clients[1]
    client_2 = comms_clients[2]

    # subscribe to self, then unsubscribe from self
    client_1.subscribe_to(client_1.rsk_address.address)
    assert client_1._is_subscribed_to(client_1.rsk_address.address) is True
    assert client_1._is_subscribed_to(client_2.rsk_address.address) is False

    client_2.subscribe_to(client_2.rsk_address.address)
    assert client_2._is_subscribed_to(client_2.rsk_address.address) is True
    assert client_2._is_subscribed_to(client_1.rsk_address.address) is False

    client_1.unsubscribe_from(client_1.rsk_address.address)
    assert client_1._is_subscribed_to(client_1.rsk_address.address) is False
    assert client_2._is_subscribed_to(client_2.rsk_address.address) is True

    client_2.unsubscribe_from(client_2.rsk_address.address)
    assert client_2._is_subscribed_to(client_2.rsk_address.address) is False


@pytest.mark.parametrize("nodes_to_clients", [{"A": 1, "B": 1}, {"A": 2}])
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


def test_client_timeouts():
    nodes = []
    try:
        node = CommsNode(CommsConfig(node_id="A", amount_of_clients=1, auto_connect=False))
        nodes.append(node)
        client = node.clients[0]

        client.grpc_client_timeout = 1e-100

        utility_addr = generate_address()
        expected_timeout_message = "Deadline Exceeded"

        # connect timeout
        expect_error(
            expected_exception=TimeoutException,
            expected_mapped_type=None,
            expected_code=StatusCode.DEADLINE_EXCEEDED,
            expected_message=expected_timeout_message,
            call=client.connect
        )

        # _get_peer_id timeout
        expect_error(
            expected_exception=TimeoutException,
            expected_mapped_type=None,
            expected_code=StatusCode.DEADLINE_EXCEEDED,
            expected_message=expected_timeout_message,
            call=client._get_peer_id,
            rsk_address=utility_addr
        )

        # _is_subscribed_to timeout
        expect_error(
            expected_exception=TimeoutException,
            expected_mapped_type=None,
            expected_code=StatusCode.DEADLINE_EXCEEDED,
            expected_message=expected_timeout_message,
            call=client._is_subscribed_to,
            rsk_address=client.rsk_address.address
        )

        # send message timeout
        expect_error(
            expected_exception=TimeoutException,
            expected_mapped_type=None,
            expected_code=StatusCode.DEADLINE_EXCEEDED,
            expected_message=expected_timeout_message,
            call=client.send_message,
            payload="echo message",
            rsk_address=utility_addr,
        )

        # unsubscribe_from timeout
        expect_error(
            expected_exception=TimeoutException,
            expected_mapped_type=None,
            expected_code=StatusCode.DEADLINE_EXCEEDED,
            expected_message=expected_timeout_message,
            call=client.unsubscribe_from,
            rsk_address=client.rsk_address.address
        )
    finally:
        for node in nodes:
            node.stop()


def expect_error(
    expected_exception: Union[ClientException, RpcError],
    expected_mapped_type: Union[ClientException, None],
    expected_code: StatusCode,
    expected_message: str,
    call: Callable,
    *args, **kwargs
):
    """
        This function checks if an exception of the ClientException type is raised during the given call
        and if that exception has some specific code and message.
    """
    with pytest.raises(expected_exception) as e:
        call(*args, **kwargs)

    if expected_mapped_type:
        client_exception = ClientExceptionHandler.map_exception(e.value)
        assert type(client_exception) == expected_mapped_type
    else:
        client_exception = e.value

    assert client_exception.code == expected_code
    assert client_exception.message == expected_message
