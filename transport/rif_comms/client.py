from eth_typing import Address

from transport.message import Message
from transport.rif_comms.proto.api_pb2 import Notification, Void


class RifCommsClient:
    """
    SDK like class to connect and operate against a RIF Communications pub-sub node.
    """

    def __init__(self, node_address: Address, grpc_api_endpoint: str):
        """
        Constructs the RifCommsClient
        :param node_address: address of the node that wants to use the RIF Comms server
        :param grpc_api_endpoint: http uri of the RIF Communications pub-sub node
        """
        self.node_address = node_address

    def connect(self, node_address: Address) -> Notification:
        """
        Connects to RIF Communications Node.
        Invokes ConnectToCommunicationsNode grpc api endpoint.
        :param node_address:  address of the client node that is trying to connect.
        :return: Notification stream
        """
        raise NotImplementedError

    def create_topic(self, partner_address: Address) -> Notification:
        """
        Creates a pub-sub topic between self.node_address and partner_address.
        Invokes CreateTopicWithRskAddress grpc api endpoint.
        :param partner_address:
        :return: Notification stream
        """
        raise NotImplementedError

    def send_message(self, receiver: Address, message: Message) -> Void:
        """
        Sends a message to receiver node.
        Invokes the SendMessageToTopic grpc api endpoint
        :param receiver: rsk address of the receiver node
        :param message: the message data
        :return: void
        """
        raise NotImplementedError

    def close_topic(self, topic_id: str) -> Void:
        """
        Closes the topic identified as topic_id.
        Invokes the CloseTopic grpc api endpoint.
        :param topic_id: topic identifier
        :return: void
        """
        raise NotImplementedError

    def disconnect(self) -> Void:
        """
        Disconnects from RIF Communications Node.
        Invokes the EndCommunication grpc api endpoint.
        :return: void
        """
        raise NotImplementedError
