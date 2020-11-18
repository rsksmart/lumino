import json
import secrets
import unittest

import grpc
import pytest
from coincurve import PublicKey
from eth_utils import to_checksum_address
from grpc._channel import _InactiveRpcError
from sha3 import keccak_256

from transport.rif_comms.client import RifCommsClient
from transport.rif_comms.proto.api_pb2 import RskAddress, Channel, Subscriber, PublishPayload, Msg
from transport.rif_comms.proto.api_pb2_grpc import CommunicationsApiStub


def get_random_address_str() -> str:
    private_key = keccak_256(secrets.token_bytes(32)).digest()
    public_key = PublicKey.from_valid_secret(private_key).format(compressed=False)[1:]
    addr = keccak_256(public_key).digest()[-20:]
    return to_checksum_address(addr)


LUMINO_1_ADDRESS = "0xe717e81105471648a152381aE6De4c878343E2sb2"
LUMINO_1_COMMS_API = "localhost:5013"

LUMINO_2_COMMS_API = "localhost:5016"
LUMINO_2_ADDRESS = "0x138af366e0ed7cc4b9747a935d1b5f75a86b9d83"

LUMINO_3_ADDRESS = "0x636BA79E46E0594ECbbEBb4F74B9336Fd4454442"


UNREGISTERED_ADDRESS = get_random_address_str()


@pytest.mark.usefixtures("rif_comms_client")
@pytest.fixture(scope="class")
def rif_comms_client(request):
    rif_comms_client1 = RifCommsClient(LUMINO_1_ADDRESS, LUMINO_1_COMMS_API)
    rif_comms_client2 = RifCommsClient(LUMINO_3_ADDRESS, LUMINO_1_COMMS_API)

    def teardown():
        rif_comms_client1.disconnect()
        rif_comms_client2.disconnect()

    request.addfinalizer(teardown)
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
    def test_initialization(self):
        assert self.rif_comms_client1 is not None

    @pytest.mark.skip(reason="ignore")
    def test_locate_peer_id(self):
        response = self.rif_comms_client1.connect()
        peer_id = self.rif_comms_client1.get_peer_id(LUMINO_1_ADDRESS)
        print(f"test_locate_peer_id peer_id = {peer_id}")
        assert peer_id is not None

    @pytest.mark.skip(reason="ignore")
    def test_locate_unregistered_peer_id(self):
        self.assertRaises(_InactiveRpcError, lambda: self.rif_comms_client1.get_peer_id(UNREGISTERED_ADDRESS))

    @pytest.mark.skip(reason="ignore")
    def test_create_random_topic_id_without_connection(self):
        notification = self.rif_comms_client1.connect()
        peer_id = self.rif_comms_client1.get_peer_id(LUMINO_1_ADDRESS)
        channel = self.rif_comms_client1.subscribe(get_random_address_str())
        peer_id = self.rif_comms_client1.get_peer_id(LUMINO_1_ADDRESS)

    @pytest.mark.skip(reason="ignore")
    def test_subscribe(self):
        channel = grpc.insecure_channel(LUMINO_1_COMMS_API)
        stub = CommunicationsApiStub(channel)
        rsk_address = RskAddress(address=LUMINO_1_ADDRESS)
        notification = stub.ConnectToCommunicationsNode(rsk_address)
        channel = stub.CreateTopicWithRskAddress(rsk_address)
        subscribers = stub.GetSubscribers(Channel(channelId=LUMINO_1_ADDRESS))

    @pytest.mark.skip(reason="ignore")
    def test_has_subscriber(self):
        channel = grpc.insecure_channel(LUMINO_1_COMMS_API)
        stub = CommunicationsApiStub(channel)
        rsk_address = RskAddress(address=LUMINO_1_ADDRESS)
        notification = stub.ConnectToCommunicationsNode(rsk_address)
        channel = stub.CreateTopicWithPeerId(rsk_address)
        peer_id = stub.LocatePeerId(rsk_address)

        """
        message Subscriber {
            string peerId = 1;
            Channel channel = 2;
        }
        """
        has_subscriber = stub.HasSubscriber(
            Subscriber(
                peerId=peer_id.address,
                channel=Channel(channelId=LUMINO_1_ADDRESS)
            )
        )
        print("has_subscriber", has_subscriber)

    @pytest.mark.skip(reason="ignore")
    def test_disconnect(self):
        notification = self.rif_comms_client1.connect()
        peer_id = self.rif_comms_client1.get_peer_id(LUMINO_1_ADDRESS)
        self.rif_comms_client1.disconnect()

    @pytest.mark.skip(reason="ignore")
    def test_send_lumino_message(self):
        channel = grpc.insecure_channel(LUMINO_2_COMMS_API)
        stub = CommunicationsApiStub(channel)
        channel = stub.Subscribe(Channel(
            channelId="16Uiu2HAm9otWzXBcFm7WC2Qufp2h1mpRxK1oox289omHTcKgrpRA"))  # got this from subscription of lumino node

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
    def test_two_clients_same_topic_subscription(self):
        """
         Right now this works but fails on the rif comms node because of this.peer_id.eq is not a function.
         We can only subscribe to the registered address

        """
        notification_stream_1 = self.rif_comms_client1.connect()
        peer_id_1 = self.rif_comms_client1.get_peer_id(LUMINO_1_ADDRESS)

        notification_stream_2 = self.rif_comms_client2.connect()
        peer_id_2 = self.rif_comms_client2.get_peer_id(LUMINO_1_ADDRESS)

        random_topic_id = get_random_address_str()
        subscription1 = self.rif_comms_client1.subscribe(random_topic_id)

        subscription2 = self.rif_comms_client2.subscribe(random_topic_id)


    @pytest.mark.skip(reason="ignore")
    def test_two_clients_different_topic_subscription(self):
        """
         This actually works but only because the client1 registered address is lumino 1 and
         the client2 registered address is lumino 3 specifically.

        """
        notification_stream_1 = self.rif_comms_client1.connect()
        peer_id_1 = self.rif_comms_client1.get_peer_id(LUMINO_1_ADDRESS)

        notification_stream_2 = self.rif_comms_client2.connect()
        peer_id_2 = self.rif_comms_client2.get_peer_id(LUMINO_1_ADDRESS)

        subscription1 = self.rif_comms_client1.subscribe(LUMINO_1_ADDRESS)

        subscription2 = self.rif_comms_client2.subscribe(LUMINO_3_ADDRESS)

    @pytest.mark.skip(reason="ignore")
    def test_two_clients_same_topic_subscription_using_subscribe(self):
        """
         Right now this works but fails on the rif comms node because of this.peer_id.eq is not a function.
         We can only subscribe to the registered address

        """
        notification_stream_1 = self.rif_comms_client1.connect()
        peer_id_1 = self.rif_comms_client1.get_peer_id(LUMINO_1_ADDRESS)

        notification_stream_2 = self.rif_comms_client2.connect()
        peer_id_2 = self.rif_comms_client2.get_peer_id(LUMINO_1_ADDRESS)

        random_topic_id = get_random_address_str()

        subscription1 = self.rif_comms_client1.stub.Subscribe(Channel(channelId=random_topic_id))
        subscription2 = self.rif_comms_client2.stub.Subscribe(Channel(channelId=random_topic_id))

        """
            connectToCommunicationsNode {"address":"0xe717e81105471648a152381aE6De4c878343E2sb2","exclusive":false}
            Adding RSKADDRESS PEER= 16Uiu2HAm9otWzXBcFm7WC2Qufp2h1mpRxK1oox289omHTcKgrpRA  : RSKADDRESS= 0xe717e81105471648a152381aE6De4c878343E2sb2
            locatePeerID "0xe717e81105471648a152381aE6De4c878343E2sb2" 
            connectToCommunicationsNode {"address":"0x636BA79E46E0594ECbbEBb4F74B9336Fd4454442","exclusive":false}
            Adding RSKADDRESS PEER= 16Uiu2HAm9otWzXBcFm7WC2Qufp2h1mpRxK1oox289omHTcKgrpRA  : RSKADDRESS= 0x636BA79E46E0594ECbbEBb4F74B9336Fd4454442
             - New subscription to 0xe2C21982c47986618C971d917ba99D4aad299401
            already subscribed

        """

        for resp in subscription2:
            print("Response for already subscribed ", resp)





