import time

import pytest

from raiden.tests.integration.network.transport.utils import generate_address
from raiden.utils import Address
from transport.rif_comms.client import Client as RIFCommsClient
from transport.rif_comms.utils import notification_to_payload

connections = {}  # hack to get around the fact that each connect() call needs to be assigned


class CommsNode:
    def __init__(self, address: Address, api: str):
        self.address = address
        self.api = api
        self.client = RIFCommsClient(rsk_address=address, grpc_api_endpoint=api)
        self.start()
        self.connect()

    def start(self):
        # TODO: start shell process
        pass

    def connect(self):
        # TODO: connect() calls should not need assignment (let alone to a module variable!)
        connections[self.address] = self.client.connect()

    def disconnect(self):
        del connections[self.address]
        self.client.disconnect()


@pytest.fixture()
@pytest.mark.parametrize("amount_of_nodes")
def comms_nodes(amount_of_nodes) -> {CommsNode}:
    nodes = {}

    def generate_comms_api(node_number: int) -> str:
        starting_port = 5013
        return "localhost:" + str(starting_port + (node_number - 1) * 1000)  # 5013, 6013, 7013...

    # setup
    for i in range(1, amount_of_nodes + 1):
        nodes[i] = CommsNode(generate_address(), generate_comms_api(i))

    yield nodes

    # TODO: connect() should block
    time.sleep(5)  # hack to wait for connect() to finish in case it has not

    # teardown
    for node in nodes.values():
        node.disconnect()


@pytest.mark.parametrize("amount_of_nodes", [1])
def test_locate_own_peer_id(comms_nodes):
    comms_node = comms_nodes[1]
    assert comms_node.client._get_peer_id(comms_node.address) is not ""


# TODO: causes ERR_NO_PEERS_IN_ROUTING_TABLE in comms node although it passes
@pytest.mark.parametrize("amount_of_nodes", [1])
def test_locate_unregistered_peer_id(comms_nodes):
    comms_node = comms_nodes[1]
    assert comms_node.client._get_peer_id(generate_address()) is ""


# TODO: comms node prints strange ServerUnaryCall message
@pytest.mark.parametrize("amount_of_nodes", [1])
def test_has_subscriber_self(comms_nodes):
    comms_node = comms_nodes[1]

    client = comms_node.client
    address = comms_node.address

    client.subscribe_to(address)

    assert client.is_subscribed_to(address) is True


@pytest.mark.skip(reason="hangs when attempting to sub 1 to 2 without subbing 2 to 2 before")
def test_has_subscriber(self):
    # register nodes 1 and 2, subscribe from 1 to 2, check subscriptions
    notification_1 = self.client_1.connect()
    notification_2 = self.client_2.connect()
    _, _ = self.client_1.subscribe_to(self.address_2)
    assert self.client_1.is_subscribed_to(self.address_1) is False
    assert self.client_1.is_subscribed_to(self.address_2) is True
    assert self.client_2.is_subscribed_to(self.address_2) is False
    assert self.client_2.is_subscribed_to(self.address_2) is False


@pytest.mark.skip(reason="hangs when attempting to sub 1 to 2 without subbing 2 to 2 before")
def test_two_clients_cross_subscription(self):
    # register nodes 1 and 2
    notification_1 = self.client_1.connect()
    notification_2 = self.client_2.connect()

    # subscribe to 1 and 2 on both nodes
    self.client_1.subscribe_to(self.address_1)
    self.client_1.subscribe_to(self.address_2)
    self.client_2.subscribe_to(self.address_1)
    self.client_2.subscribe_to(self.address_2)

    assert self.client_1.is_subscribed_to(self.address_1) is True
    assert self.client_1.is_subscribed_to(self.address_2) is True
    assert self.client_2.is_subscribed_to(self.address_1) is True
    assert self.client_2.is_subscribed_to(self.address_2) is True


@pytest.mark.skip(reason="incomplete test")
def test_disconnect(self):
    # register node 1, get own peer id, disconnect
    notification = self.client_1.connect()
    peer_id = self.client_1._get_peer_id(self.address_1)
    self.client_1.disconnect()
    # TODO check if end comms deletes topics


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
