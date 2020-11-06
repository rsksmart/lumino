import unittest

import grpc
import pytest
from grpc._channel import _InactiveRpcError

from transport.rif_comms.client import RifCommsClient

LUMINO_1_ADDRESS = "0x5Ec92458ACD047f3B583E09C243a480Ef54A68D4"
LUMINO_1_COMMS_API = "localhost:5013"

UNREGISTERED_ADDRESS = "0xf810afadaa020c697baab0fb64d8cf1c1b70e1ec"


@pytest.fixture(scope="class")
def rif_comms_client(request):
    rif_comms_client = RifCommsClient(LUMINO_1_ADDRESS, LUMINO_1_COMMS_API)
    rif_comms_client.connect()

    def teardown():
        rif_comms_client.disconnect()

    request.addfinalizer(teardown)
    request.cls.rif_comms_client = rif_comms_client


@pytest.mark.usefixtures("rif_comms_client")
class TestRiffCommsClient(unittest.TestCase):
    def test_initialization(self):
        assert self.rif_comms_client is not None

    def test_locate_peer_id(self):
        peer_id = self.rif_comms_client.locate_peer_id(LUMINO_1_ADDRESS)
        print(f"test_locate_peer_id peer_id = {peer_id}")
        assert peer_id is not None

    def test_locate_unregistered_peer_id(self):
        self.assertRaises(_InactiveRpcError, lambda: self.rif_comms_client.locate_peer_id(UNREGISTERED_ADDRESS))
