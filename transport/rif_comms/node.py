from typing import Any

from raiden.message_handler import MessageHandler
from raiden.messages import Message
from raiden.raiden_service import RaidenService
from raiden.utils.typing import Address
from transport.node import Node as TransportNode
from transport.rif_comms.client import RifCommsClient


class RifCommsNode(TransportNode):

    def __init__(self, address: Address, config: dict):
        TransportNode.__init__(self, address)
        self._config = config

        self._client = RifCommsClient("0x5Ec92458ACD047f3B583E09C243a480Ef54A68D4", self._config["grpc_endpoint"])
        self._client.connect()
        self._client.locate_peer_id("0x5Ec92458ACD047f3B583E09C243a480Ef54A68D4")
        print("RifCommsNode init on grpc endpoint: {}".format(self._config["grpc_endpoint"]))
        self._client.disconnect()
        print("Disconnected")

    def start(self, raiden_service: RaidenService, message_handler: MessageHandler, prev_auth_data: str):
        raise NotImplementedError

    def stop(self):
        raise NotImplementedError

    def enqueue_message(self, message: Message, recipient: Address):
        raise NotImplementedError

    def enqueue_global_messages(self):
        raise NotImplementedError

    def send_message(self, recipient: Address, message_data: str):
        raise NotImplementedError

    def start_health_check(self, address: Address):
        raise NotImplementedError

    def whitelist(self, address: Address):
        raise NotImplementedError

    def link_exception(self, callback: Any):
        raise NotImplementedError

    def join(self, timeout=None):
        raise NotImplementedError

    def raiden_service(self) -> 'RaidenService':
        raise NotImplementedError

    def config(self) -> {}:
        raise NotImplementedError

    def log(self):
        raise NotImplementedError

    def _run(self, *args: Any, **kwargs: Any) -> None:
        raise NotImplementedError


class RifCommsLightClientNode(RifCommsNode):

    def __init__(self, address: Address, config: dict, auth_params: dict):
        RifCommsNode.__init__(self, address, config)
