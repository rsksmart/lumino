import json

from eth_utils import to_canonical_address

from raiden.utils import Address
from transport.rif_comms.proto.api_pb2 import ChannelNewData


def notification_to_payload(notification_data: ChannelNewData) -> str:
    """
    :param notification_data: raw data received by the RIF Comms GRPC API
    :return: a message payload
    """
    content_data = notification_data.channelNewData.data
    """
    ChannelNewData has the following structure:
        peer:  {
          address: "16Uiu2HAmV4KttHooePhKsDsHQTJUzHH6FLv1hRA86hT5Js994hFz"
        }
        sender {
          address: "0xB2D3c4055C4d6B3832a1ee0eF8a5EB25F4D56292"
        }
        data: "{\"type\":\"Buffer\",\"data\":[104,101,121]}"
        nonce: "\216f\225\232d\023e{"
        channel {
          channelId: "16Uiu2HAm9otWzXBcFm7WC2Qufp2h1mpRxK1oox289omHTcKgrpRA"
        }
    """
    if content_data:
        content = json.loads(content_data.decode())  # deserialize `data` dict
        return bytes(content["data"]).decode()  # deserialize `data.data` field
    return ""


def get_sender_from_notification(notification_data: ChannelNewData) -> Address:
    return to_canonical_address(notification_data.channelNewData.sender.address)

