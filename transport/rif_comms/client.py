from eth_utils import to_checksum_address
from grpc import insecure_channel

from raiden.utils import Address
from transport.rif_comms.proto.api_pb2 import (
    Notification,
    PublishPayload,
    Channel,
    Msg,
    RskAddress,
    Void,
    Subscriber
)
from transport.rif_comms.proto.api_pb2_grpc import CommunicationsApiStub


class Client:
    """
    Class to connect and operate against a RIF Communications pub-sub node.
    """

    def __init__(self, rsk_address: Address, grpc_api_endpoint: str):
        """
        Constructs the RIF Communications Client.
        :param rsk_address: RSK address of the node that wants to use the RIF Communications server
        :param grpc_api_endpoint: GRPC URI of the RIF Communications pub-sub node
        """
        self.rsk_address = RskAddress(address=to_checksum_address(rsk_address))
        self.grpc_channel = insecure_channel(grpc_api_endpoint)  # TODO: how to make this secure?
        self.stub = CommunicationsApiStub(self.grpc_channel)

    def connect(self) -> Notification:
        """
        Connects to RIF Communications Node.
        Invokes ConnectToCommunicationsNode GRPC API endpoint.
        Adds the client RSK address under the RIF Communications node peer ID.
        :return: notification stream
        """
        return self.stub.ConnectToCommunicationsNode(self.rsk_address)

    def subscribe_to(self, rsk_address: Address) -> (str, Notification):
        """
        Subscribes to a pub-sub topic in order to send messages to or receive messages from an address.
        Invokes CreateTopicWithRskAddress GRPC API endpoint.
        The resulting notification stream should only be used for receiving messages; use send_message for sending.
        :param rsk_address: destination RSK address for message sending
        :return: peer id and notification stream for receiving messages
        """
        topic_id = None
        # TODO: catch already subscribed and any error
        topic = self.stub.CreateTopicWithRskAddress(RskAddress(address=to_checksum_address(rsk_address)))
        for response in topic:
            topic_id = response.channelPeerJoined.peerId
            break
        return topic_id, topic

    def is_subscribed_to(self, rsk_address: Address) -> bool:
        """
        Returns whether or not the client's underlying RIF Communications node is subscribed to the topic
        which corresponds to the given RSK address.
        Invokes HasSubscriber GRPC API endpoint.
        :param rsk_address: RSK address which corresponds to the topic which is being checked for subscription
        :return: boolean value indicating whether the client is subscribed or not
        """
        topic_id = self._get_peer_id(rsk_address)
        return self.stub.HasSubscriber(
            Subscriber(
                peerId=topic_id,
                channel=Channel(channelId=topic_id)
            )
        ).value

    def send_message(self, payload: str, rsk_address: Address):
        """
        Sends a message to a destination RSK address.
        Invokes the SendMessageToTopic GRPC API endpoint.
        :param payload: the message data to be sent
        :param rsk_address: the destination for the message to be sent to
        """
        topic_id = self._get_peer_id(to_checksum_address(rsk_address))
        # TODO: message encoding
        self.stub.SendMessageToTopic(
            PublishPayload(
                topic=Channel(channelId=topic_id),
                message=Msg(payload=str.encode(payload))
            )
        )

    def unsubscribe_from(self, rsk_address: Address):
        """
        Unsubscribes from a topic which corresponds to the given RSK address.
        Invokes the CloseTopic GRPC API endpoint.
        :param rsk_address: RSK address which corresponds to the topic which the client is unsubscribing from.
        """
        topic_id = self._get_peer_id(to_checksum_address(rsk_address))
        self.stub.CloseTopic(Channel(channelId=topic_id))

    def disconnect(self):
        """
        Disconnects from RIF Communications Node.
        """
        self.grpc_channel.unsubscribe(lambda: self.grpc_channel.close())

    def _get_peer_id(self, rsk_address: Address) -> str:
        """
        Gets the peer ID associated with a node RSK address.
        :param rsk_address: the RSK address which corresponds to the node to locate
        :return: a string that represents the peer ID that matches the given address
        :raises:
            - No peers from routing table:
                exception: _InactiveRpcError
                status = StatusCode.UNKNOWN
                details = "Failed to lookup key! No peers from routing table!"
        """
        return self.stub.LocatePeerId(RskAddress(address=to_checksum_address(rsk_address))).address

    def end_communications(self):
        """
        Invokes the EndCommunication GRPC API endpoint.
        """
        self.stub.EndCommunication(Void())
