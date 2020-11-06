import grpc
from grpc import insecure_channel

from transport.rif_comms.client import RifCommsClient
from transport.rif_comms.proto import api_pb2_grpc
from transport.rif_comms.proto.api_pb2 import RskAddress
from transport.rif_comms.proto.api_pb2_grpc import CommunicationsApiStub

LUMINO_1_ADDRESS = "0x5Ec92458ACD047f3B583E09C243a480Ef54A68D4"
LUMINO_1_COMMS_API = "localhost:5013"


#def test_initialization():
 #   rif_comms_client_1 = RifCommsClient(LUMINO_1_ADDRESS, LUMINO_1_COMMS_API)
  #  rif_comms_client_1.connect()
   # rif_comms_client_1.locate_peer_id(LUMINO_1_ADDRESS)
    #rif_comms_client_1.disconnect()


def test_initialization_2():
    stub = connect()

    print("LocatePeerId")
    response = stub.LocatePeerId(api_pb2_grpc.api__pb2.RskAddress(address="0x2aCc95758f8b5F583470bA265Eb685a8f45fC9D5"))
    stub.ConnectToCommunicationsNode(api_pb2_grpc.api__pb2.RskAddress(address="0x2aCc95758f8b5F583470bA265Eb685a8f45fC9D5"))
    print("la concha de tu madre")

def connect():
    channel = grpc.insecure_channel("localhost:5013")
    stub = api_pb2_grpc.CommunicationsApiStub(channel)
    #stub.ConnectToCommunicationsNode(api_pb2_grpc.api__pb2.RskAddress(address="0x2aCc95758f8b5F583470bA265Eb685a8f45fC9D5"))
    return stub


