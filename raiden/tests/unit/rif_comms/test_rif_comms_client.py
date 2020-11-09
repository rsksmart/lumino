import unittest

import grpc
import pytest
from grpc._channel import _InactiveRpcError

from transport.rif_comms.client import RifCommsClient
import secrets
from sha3 import keccak_256
from coincurve import PublicKey
from eth_utils import to_checksum_address

from transport.rif_comms.proto.api_pb2 import RskAddress
from transport.rif_comms.proto.api_pb2_grpc import CommunicationsApiStub


def get_random_address_str() -> str:
    private_key = keccak_256(secrets.token_bytes(32)).digest()
    public_key = PublicKey.from_valid_secret(private_key).format(compressed=False)[1:]
    addr = keccak_256(public_key).digest()[-20:]
    return to_checksum_address(addr)


LUMINO_1_ADDRESS = "0xe798e91805471648a152381aE6De4c878343E2sb2"
LUMINO_1_COMMS_API = "localhost:5013"

LUMINO_2_COMMS_API = "localhost:5016"
LUMINO_2_ADDRESS = "0xe798e91805471D48a152382aE6De4c878343E6b2"


UNREGISTERED_ADDRESS = get_random_address_str()

#@pytest.mark.usefixtures("rif_comms_client")
#@pytest.fixture(scope="class")
#def rif_comms_client(request):
 #   rif_comms_client = RifCommsClient(LUMINO_1_ADDRESS, LUMINO_1_COMMS_API)

  #  def teardown():
   #     rif_comms_client.disconnect()

    #request.addfinalizer(teardown)
    #request.cls.rif_comms_client = rif_comms_client


#@pytest.mark.usefixtures("rif_comms_client")
class TestRiffCommsClient(unittest.TestCase):
    @pytest.mark.skip(reason="ignore")
    def test_initialization(self):
        rif_comms_client = RifCommsClient(LUMINO_1_ADDRESS, LUMINO_1_COMMS_API)
        assert rif_comms_client is not None

    @pytest.mark.skip(reason="ignore")
    def test_locate_peer_id(self):
        rif_comms_client = RifCommsClient(LUMINO_1_ADDRESS, LUMINO_1_COMMS_API)
        response = rif_comms_client.connect()
        peer_id = rif_comms_client.locate_peer_id(LUMINO_1_ADDRESS)
        print(f"test_locate_peer_id peer_id = {peer_id}")
        assert peer_id is not None

    @pytest.mark.skip(reason="ignore")
    def test_locate_unregistered_peer_id(self):
        rif_comms_client = RifCommsClient(LUMINO_1_ADDRESS, LUMINO_1_COMMS_API)
        self.assertRaises(_InactiveRpcError, lambda: rif_comms_client.locate_peer_id(UNREGISTERED_ADDRESS))

    def test_create_random_topic_id_without_connection(self):
        rif_comms_client = RifCommsClient(LUMINO_1_ADDRESS, LUMINO_1_COMMS_API)
        notification=rif_comms_client.connect()
        peer_id = rif_comms_client.locate_peer_id(LUMINO_1_ADDRESS)
        channel=rif_comms_client.create_topic(get_random_address_str())
        peer_id = rif_comms_client.locate_peer_id(LUMINO_1_ADDRESS)

    @pytest.mark.skip(reason="ignore")
    def test_create_random_topic_id_without_connection_1(self):
        channel = grpc.insecure_channel(LUMINO_1_COMMS_API)
        stub = CommunicationsApiStub(channel)
        rsk_address = RskAddress(address=LUMINO_1_ADDRESS)
        peer_addr = RskAddress(address=get_random_address_str())
        notification = stub.ConnectToCommunicationsNode(rsk_address)
        response = stub.LocatePeerId(rsk_address)
        print("response=%s" % response)
        channel = stub.CreateTopicWithRskAddress(peer_addr)
        for resp in channel:
            print(resp)

