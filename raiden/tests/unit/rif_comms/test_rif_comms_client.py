import json
import unittest

import grpc
import pytest
from eth_utils import to_canonical_address
from transport.rif_comms.client import Client as RIFCommsClient
from transport.rif_comms.node import Node as RIFCommsNode
from transport.rif_comms.proto.api_pb2 import Channel, PublishPayload, Msg
from transport.rif_comms.proto.api_pb2_grpc import CommunicationsApiStub

test_nodes = dict([
    (1, {
        "address": to_canonical_address("0x8cb891510dF75C223C53f910A98c3b61B9083c3B"),
        "comms-api": "localhost:5013",
    }),
    (2, {
        "address": to_canonical_address("0xeBfF0EEe8E2b6952E589B0475e3F0E34dA0655B1"),
        "comms-api": "localhost:6013",
    }),
    (3, {
        "address": to_canonical_address("0x636BA79E46E0594ECbbEBb4F74B9336Fd4454442"),
        "comms-api": "localhost:7013",
    }),
])


@pytest.mark.usefixtures("rif_comms_client")
@pytest.fixture(scope="class")
def rif_comms_client(request):
    address_1 = test_nodes[1]["address"]
    api_1 = test_nodes[1]["comms-api"]
    client_1 = RIFCommsClient(test_nodes[1]["address"], test_nodes[1]["comms-api"])

    address_2 = test_nodes[2]["address"]
    api_2 = test_nodes[2]["comms-api"]
    client_2 = RIFCommsClient(test_nodes[2]["address"], test_nodes[2]["comms-api"])

    def teardown():
        client_1.disconnect()
        client_2.disconnect()

    # request.addfinalizer(teardown)
    request.cls.client_1 = client_1
    request.cls.address_1 = address_1
    request.cls.api_1 = api_1

    request.cls.client_2 = client_2
    request.cls.address_2 = address_2
    request.cls.api_2 = api_2


@pytest.mark.usefixtures("rif_comms_client")
class TestRIFCommsClient(unittest.TestCase):
    """
    Test for RIFCommsClient. This class is for test the basic operations of the client.

    How to use it:

    - modify the test_nodes address and rif_comms_api fields
    - addresses are used as representations of the Lumino keystore
    - each of the nodes is used as a separate peer
    - all tests assume that there is a RIF COMMS node already running
    """

    @pytest.mark.skip(reason="succeeds no matter what")
    def test_connect(self):
        response = self.client_1.connect()
        assert response is not None

    @pytest.mark.skip(reason="fails without the response assignment")
    def test_locate_own_peer_id(self):
        # register node 1, locate node 1
        response = self.client_1.connect()
        assert self.client_1._get_peer_id(self.address_1) is not ""

    @pytest.mark.skip(reason="causes ERR_NO_PEERS_IN_ROUTING_TABLE in comms node although it passes")
    def test_locate_unregistered_peer_id(self):
        # register node 1, locate node 2
        response = self.client_1.connect()
        assert self.client_1._get_peer_id(self.address_2) is ""

    @pytest.mark.skip(reason="requires running rif comms node")
    def test_has_subscriber_self(self):
        # register node 1, subscribe to self, check subscription
        notification = self.client_1.connect()
        self.client_1.subscribe_to(self.address_1)
        assert self.client_1.is_subscribed_to(self.address_1) is True

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

    @pytest.mark.skip(reason="fails due to as-of-yet undetermined reason, used to work")
    def test_send_lumino_message(self):
        # this test requires a lumino node started with a comms api matching test_nodes[1]["comms_api"]
        stub = CommunicationsApiStub(grpc.insecure_channel(self.api_1))

        # TODO: obtain this programmatically
        channel_id = "16Uiu2HAmQmHFGepf3eaptGCkPhhw8ggipsrJzZyLTrnd5TJKWDHk"
        # got this from subscription of lumino node

        sub = stub.Subscribe(Channel(channelId=channel_id))
        print("sub")

        some_raiden_message = {
            'type': 'LockedTransfer',
            'chain_id': 33,
            'message_identifier': 9074731958492744333,
            'payment_identifier': 2958725218135700941,
            'payment_hash_invoice': '0x0000000000000000000000000000000000000000000000000000000000000000',
            'nonce': 45,
            'token_network_address': '0xd548700d98f32f83b3c88756cf340b7f61877d75',
            'token': '0xf563b16dc42d9cb6d7ca31793f2d62131d586d05',
            'channel_identifier': 12,
            'transferred_amount': 17000000000000000000,
            'locked_amount': 1000000000000000000,
            'recipient': '0x00e8249ee607ea67127c4add69291a6c412603c5',
            'locksroot': '0x043c092c72059c4c154cb342409d95364888a98fa87efadece5add9c255dce9a',
            'lock': {
                'type': 'Lock',
                'amount': 1000000000000000000,
                'expiration': 1165251,
                'secrethash': '0x2dc5a7ff26be395d443200db5d16b5d2aadae3a83836be648cd4cba8e2e555fe'
            },
            'target': '0x00e8249ee607ea67127c4add69291a6c412603c5',
            'initiator': '0x27633dc87378a551f09f2fcf43a48fc2b3425d43',
            'fee': 0,
            'signature': '0xbaa4df61ab23ab8fdddf4a90fd5db7dd04da364795ebb717426bdd1fcefb411759e1b41d71c3c54b2a75c3eba0f2a2c54c846a0139120ee794f51b0e2a0d954d1c'
        }

        stub.SendMessageToTopic(
            PublishPayload(
                topic=Channel(channelId=channel_id),
                message=Msg(payload=str.encode(json.dumps(some_raiden_message)))
            )
        )

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
            received_message = RIFCommsNode._notification_to_message(resp)
            assert received_message == payload_1
            break  # only 1 message is expected

        for resp in two_sub_one:
            received_message = RIFCommsNode._notification_to_message(resp)
            assert received_message == payload_2
            break  # only 1 message is expected
