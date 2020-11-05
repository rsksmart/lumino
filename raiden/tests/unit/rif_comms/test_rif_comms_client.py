from transport.rif_comms.client import RifCommsClient

LUMINO_1_ADDRESS = "0x5Ec92458ACD047f3B583E09C243a480Ef54A68D4"
LUMINO_1_COMMS_API = "localhost:5013"


def test_initialization():
    rif_comms_client_1 = RifCommsClient(LUMINO_1_ADDRESS, LUMINO_1_COMMS_API)
    rif_comms_client_1.connect()
    rif_comms_client_1.locate_peer_id(LUMINO_1_ADDRESS)
