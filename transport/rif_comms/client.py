from eth_typing import Address
from grpc import insecure_channel

from transport.message import Message
from transport.rif_comms.proto.api_pb2 import Notification, Void, PublishPayload, Channel, Msg, RskAddress
from transport.rif_comms.proto.api_pb2_grpc import CommunicationsApiStub


class RifCommsClient:
    """
    Class to connect and operate against a RIF Communications pub-sub node.
    """

    def __init__(self, rsk_address: Address, grpc_api_endpoint: str):
        """
        Constructs the Rif Communications Client
        :param rsk_address: address of the node that wants to use the RIF Comms server
        :param grpc_api_endpoint: grpc uri of the RIF Communications pub-sub node
        """
        self.rsk_address = RskAddress(address=rsk_address)
        self.grpc_channel = insecure_channel(grpc_api_endpoint)
        self.stub = CommunicationsApiStub(self.grpc_channel)

    def connect(self) -> Notification:
        """
        Connects to RIF Communications Node.
        Invokes ConnectToCommunicationsNode grpc api endpoint.
        :return: Notification stream
        """
        return self.stub.ConnectToCommunicationsNode(self.rsk_address)

    def create_topic(self, rsk_address: Address) -> Notification:
        """
        Creates a pub-sub topic between self.rsk_address and partner_address.
        Invokes CreateTopicWithRskAddress grpc api endpoint.
        :param rsk_address:
        :return: Notification stream
        """
        # TODO catch already subscribed and any error
        return self.stub.CreateTopicWithRskAddress(RskAddress(address=rsk_address))

    def send_message(self, topic_id: Address, message: Message) -> Void:
        """
        Sends a message to receiver node.
        Invokes the SendMessageToTopic grpc api endpoint
        :param topic_id: topic identifier
        :param message: the message data
        :return: void
        """

        # TODO message encoding
        self.stub.SendMessageToTopic(
            PublishPayload(
                topic=Channel(channelId=topic_id),
                message=Msg(payload=str.encode("Test message"))
            )
        )

    def close_topic(self, topic_id: str) -> Void:
        """
        Closes the topic identified as topic_id, this unsubscribe the node from the topic.
        Invokes the CloseTopic grpc api endpoint.
        :param topic_id: topic identifier
        :return: void
        """
        self.stub.CloseTopic(Channel(channelId=topic_id))

    def disconnect(self) -> Void:
        """
        Disconnects from RIF Communications Node.
        Invokes the EndCommunication grpc api endpoint.
        :return: void
        """
        def close(channel):
            channel.close()
        self.grpc_channel.unsubscribe(close)

    def locate_peer_id(self, rsk_address: Address) -> str:
        """
        Gets the peer ID associated with a node address
        :param rsk_address: the node address to locate
        :return: a string that represents the peer ID
        """
        return self.stub.LocatePeerId(RskAddress(address=rsk_address)).address
