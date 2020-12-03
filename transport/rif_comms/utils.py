import json

from transport.rif_comms.proto.api_pb2 import ChannelNewData


def notification_to_payload(notification_data: ChannelNewData) -> str:
    """
    :param notification_data: raw data received by the RIF Comms GRPC API
    :return: a message payload
    """
    content_data = notification_data.channelNewData.data
    """
    ChannelNewData has the following structure:
        from: "16Uiu2HAm8wq7GpkmTDqBxb4eKGfa2Yos79DabTgSXXF4PcHaDhWJ"
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
