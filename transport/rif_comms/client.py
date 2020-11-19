from grpc import insecure_channel

from raiden.utils import Address
from transport.rif_comms.proto.api_pb2 import (
    Notification,
    PublishPayload,
    Channel,
    Msg,
    RskAddress,
    Void,
    Subscriber,
    BooleanResponse
)
from transport.rif_comms.proto.api_pb2_grpc import CommunicationsApiStub


class RifCommsClient:
    """
    Class to connect and operate against a RIF Communications pub-sub node.
    """

    def __init__(self, rsk_address: Address, grpc_api_endpoint: str):
        """
        Constructs the RIF Communications Client.
        :param rsk_address: address of the node that wants to use the RIF Communications server
        :param grpc_api_endpoint: GRPC URI of the RIF Communications pub-sub node
        """
        self.rsk_address = RskAddress(address=rsk_address)
        self.grpc_channel = insecure_channel(grpc_api_endpoint)  # TODO: how to make this secure?
        self.stub = CommunicationsApiStub(self.grpc_channel)

    def connect(self) -> Notification:
        """
        Connects to RIF Communications Node.
        Invokes ConnectToCommunicationsNode GRPC API endpoint.
        Adds the client RSK Address under the RIF Communications node Peer ID.
        :return: Notification stream
        """
        return self.stub.ConnectToCommunicationsNode(self.rsk_address)

    def subscribe(self, rsk_address: Address) -> Notification:
        """
        Subscribes to a pub-sub topic in order to send messages to or receive messages from an address.
        Invokes CreateTopicWithRskAddress GRPC API endpoint.
        The resulting notification stream should only be used for receiving messages; use send_message for sending.
        :param rsk_address: destination RSK Address for message sending.
        :return: Notification stream for receiving messages.
        """
        # TODO: catch already subscribed and any error
        return self.stub.CreateTopicWithRskAddress(RskAddress(address=rsk_address))

    # TODO review params and create docstring. It has no sense to use both peer id and rsk_address
    def has_subscription(self, rsk_address: Address) -> BooleanResponse:
        peer_id = self.get_peer_id(rsk_address)
        return self.stub.HasSubscriber(
            Subscriber(
                peerId=peer_id,
                channel=Channel(channelId=rsk_address)
            )
        )

    def send_message(self, topic_id: str, data: str) -> Void:
        """
        Sends a message to a topic.
        Invokes the SendMessageToTopic grpc api endpoint
        :param topic_id: topic identifier
        :param message: the message data
        :return: void
        """

        # TODO message encoding
        return self.stub.SendMessageToTopic(
            PublishPayload(
                topic=Channel(channelId=topic_id),
                message=Msg(payload=str.encode(data))
            )
        )

    def unsubscribe(self, topic_id: str) -> Void:
        """
        This unsubscribe the node from the topic.
        Invokes the CloseTopic grpc api endpoint.
        :param topic_id: topic identifier
        :return: void
        """
        self.stub.CloseTopic(Channel(channelId=topic_id))

    def disconnect(self) -> Void:
        """
        Disconnects from RIF Communications Node.
        Invokes the EndCommunication GRPC API endpoint.
        :return: void
        """
        self.stub.EndCommunication(Void())
        self.grpc_channel.unsubscribe(lambda: self.grpc_channel.close())

    def get_peer_id(self, rsk_address: Address) -> str:
        """
        Gets the peer ID associated with a node address
        :param rsk_address: the node address to locate
        :return: a string that represents the peer ID
        :raises:
            - No peers from routing table:
                exception: _InactiveRpcError
                status = StatusCode.UNKNOWN
                details = "Failed to lookup key! No peers from routing table!"
        """
        return self.stub.LocatePeerId(RskAddress(address=rsk_address)).address
