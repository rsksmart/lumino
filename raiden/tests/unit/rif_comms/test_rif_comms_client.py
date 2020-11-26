import json
import secrets
import time
import unittest

import grpc
import pytest
from coincurve import PublicKey
from eth_utils import to_checksum_address, to_canonical_address
from grpc._channel import _InactiveRpcError
from sha3 import keccak_256

from transport.rif_comms.client import Client as RIFCommsClient
from transport.rif_comms.proto.api_pb2 import RskAddress, Channel, Subscriber, PublishPayload, Msg
from transport.rif_comms.proto.api_pb2_grpc import CommunicationsApiStub


def get_random_address_str() -> str:
    private_key = keccak_256(secrets.token_bytes(32)).digest()
    public_key = PublicKey.from_valid_secret(private_key).format(compressed=False)[1:]
    addr = keccak_256(public_key).digest()[-20:]
    return to_checksum_address(addr)


LUMINO_1_ADDRESS = to_canonical_address("0x8cb891510dF75C223C53f910A98c3b61B9083c3B")
LUMINO_1_COMMS_API = "localhost:5013"

LUMINO_2_COMMS_API = "localhost:5016"
LUMINO_2_ADDRESS = to_canonical_address("0xeBfF0EEe8E2b6952E589B0475e3F0E34dA0655B1")

LUMINO_3_ADDRESS = "0x636BA79E46E0594ECbbEBb4F74B9336Fd4454442"

UNREGISTERED_ADDRESS = get_random_address_str()


@pytest.mark.usefixtures("rif_comms_client")
@pytest.fixture(scope="class")
def rif_comms_client(request):
    rif_comms_client1 = RIFCommsClient(LUMINO_1_ADDRESS, LUMINO_1_COMMS_API)
    rif_comms_client2 = RIFCommsClient(LUMINO_2_ADDRESS, LUMINO_2_COMMS_API)

    def teardown():
        rif_comms_client1.disconnect()
        rif_comms_client2.disconnect()

    #request.addfinalizer(teardown)
    request.cls.rif_comms_client1 = rif_comms_client1
    request.cls.rif_comms_client2 = rif_comms_client2


@pytest.mark.usefixtures("rif_comms_client")
class TestRiffCommsClient(unittest.TestCase):
    """
    Test for RIFCommsClient. This class is for test the basic operations of the client.

    How to use it:

    - Modify the LUMINO_1_COMMS_API, LUMINO_2_COMMS_API, LUMINO_1_ADDRESS and LUMINO_2_ADDRESS
    - Some tests uses LUMINO_1_ADDRESS as a representation of the Lumino keystore
    - Others uses both LUMINO_1_ADDRESS and LUMINO_2_ADDRESS to represent two separeted peers
    - ALl the tests assumes that there is a RIF COMMS node already running
    """
    @pytest.mark.skip(reason="ignore")
    def test_connect(self):
        response = self.rif_comms_client1.connect()
        assert self.rif_comms_client1 is not None
        time.sleep(5)

    @pytest.mark.skip(reason="ignore")
    def test_locate_peer_id(self):
        response = self.rif_comms_client1.connect()
        peer_id = self.rif_comms_client1._get_peer_id(LUMINO_1_ADDRESS)
        print(f"test_locate_peer_id peer_id = {peer_id}")
        assert peer_id is not None

    @pytest.mark.skip(reason="ignore")
    def test_locate_unregistered_peer_id(self):
        response = self.rif_comms_client1.connect()
        peer_id = self.rif_comms_client1._get_peer_id(LUMINO_3_ADDRESS)
        print(f"test_locate_peer_id peer_id = {peer_id}")
        assert peer_id is ""

    @pytest.mark.skip(reason="ignore")
    def test_create_random_topic_id_without_connection(self):
        notification = self.rif_comms_client1.connect()
        channel = self.rif_comms_client1.subscribe_to(get_random_address_str())
        peer_id = self.rif_comms_client1._get_peer_id(LUMINO_3_ADDRESS)


    @pytest.mark.skip(reason="ignore")
    def test_has_subscriber(self):
        notification = self.rif_comms_client1.connect()
        notification2 = self.rif_comms_client2.connect()
        channel = self.rif_comms_client1.subscribe_to(LUMINO_2_ADDRESS)
        time.sleep(10)
        subscribed = self.rif_comms_client1.is_subscribed_to(LUMINO_2_ADDRESS)
        assert subscribed is True



    @pytest.mark.skip(reason="works but subscribed equals False")
    def test_has_subscriber_self(self):
        notification = self.rif_comms_client1.connect()
        channel = self.rif_comms_client1.subscribe_to(LUMINO_1_ADDRESS)
        subscribed = self.rif_comms_client1.is_subscribed_to(LUMINO_1_ADDRESS)
        assert subscribed is True

    @pytest.mark.skip(reason="ignore")
    def test_disconnect(self):
        notification = self.rif_comms_client.connect()
        peer_id = self.rif_comms_client._get_peer_id(LUMINO_1_ADDRESS)
        self.rif_comms_client.disconnect()
        # TODO check if end comms deletes topics

    @pytest.mark.skip(reason="ignore")
    def test_send_lumino_message(self):
        channel = grpc.insecure_channel(LUMINO_2_COMMS_API)
        stub = CommunicationsApiStub(channel)
        channel = stub.Subscribe(Channel(
            channelId="16Uiu2HAm9otWzXBcFm7WC2Qufp2h1mpRxK1oox289omHTcKgrpRA")
            # got this from subscription of lumino node
        )

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
                topic=Channel(channelId="16Uiu2HAm9otWzXBcFm7WC2Qufp2h1mpRxK1oox289omHTcKgrpRA"),
                message=Msg(payload=str.encode(json.dumps(some_raiden_message)))
            )
        )

    @pytest.mark.skip(reason="ignore")
    def test_two_clients_topic_subscription(self):
        notification_stream_1 = self.rif_comms_client1.connect()

        notification_stream_2 = self.rif_comms_client2.connect()

        one_own_sub = self.rif_comms_client1.subscribe_to(LUMINO_1_ADDRESS)
        one_two_sub = self.rif_comms_client1.subscribe_to(LUMINO_2_ADDRESS)

        two_own_sub = self.rif_comms_client2.subscribe_to(LUMINO_2_ADDRESS)
        two_one_sub = self.rif_comms_client2.subscribe_to(LUMINO_1_ADDRESS)

        peer_id_1 = self.rif_comms_client2._get_peer_id(LUMINO_2_ADDRESS)

    @pytest.mark.skip(reason="ignore")
    def test_two_clients_listen_same_topic(self):

        notification_stream_1 = self.rif_comms_client1.connect()

        notification_stream_2 = self.rif_comms_client2.connect()

        one_own_sub = self.rif_comms_client1.subscribe_to(LUMINO_1_ADDRESS)
        two_one_sub = self.rif_comms_client2.subscribe_to(LUMINO_1_ADDRESS)

        peer_id_1 = self.rif_comms_client2._get_peer_id(LUMINO_2_ADDRESS)

        for resp in one_own_sub:
            print("Respone for 1: ", resp)

        for resp in two_one_sub:
            print("Respone for 2: ", resp)
