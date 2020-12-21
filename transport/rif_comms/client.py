from eth_utils import to_checksum_address
from grpc import insecure_channel

from raiden.utils import Address
from transport.rif_comms.proto.api_pb2 import (
    Notification,
    Msg,
    RskAddress,
    Void,
    RskAddressPublish
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
        # FIXME: communications should not need variable assignment
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
        # TODO: catch exceptions
        # TODO: add timeout
        topic = self.stub.CreateTopicWithRskAddress(
            RskAddress(address=to_checksum_address(rsk_address))
        )
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
        return self.stub.IsSubscribedToRskAddress(
            RskAddress(address=to_checksum_address(rsk_address))
        ).value

    def send_message(self, payload: str, rsk_address: Address):
        """
        Sends a message to a destination RSK address.
        Invokes the SendMessageToTopic GRPC API endpoint.
        :param payload: the message data to be sent
        :param rsk_address: the destination for the message to be sent to
        """
        self.stub.SendMessageToRskAddress(
            RskAddressPublish(
                sender=self.rsk_address,
                receiver=RskAddress(address=to_checksum_address(rsk_address)),
                message=Msg(payload=str.encode(payload)),
            )
        )

    def unsubscribe_from(self, rsk_address: Address):
        """
        Unsubscribes from a topic which corresponds to the given RSK address.
        Invokes the CloseTopic GRPC API endpoint.
        :param rsk_address: RSK address which corresponds to the topic which the client is unsubscribing from.
        """
        self.stub.CloseTopicWithRskAddress(
            RskAddress(address=to_checksum_address(rsk_address))
        )

    def disconnect(self):
        """
         Invokes the EndCommunication GRPC API endpoint.
         Disconnects from RIF Communications Node. Closes grpc connection
        """
        # FIXME: ending communications should not need variable assignment
        disconnection = self.stub.EndCommunication(Void())
        self.grpc_channel.unsubscribe(lambda: self.grpc_channel.close())
