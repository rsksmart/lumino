from typing import Any

from raiden.message_handler import MessageHandler
from raiden.messages import Message
from raiden.raiden_service import RaidenService
from raiden.utils.runnable import Runnable
from raiden.utils.typing import Address
from transport.node import Node as TransportNode
from transport.rif_comms.client import RifCommsClient


class RifCommsNode(TransportNode, Runnable):

    def __init__(self, address: Address, config: dict):
        TransportNode.__init__(self, address)
        Runnable.__init__(self)
        self._config = config

        self._client = RifCommsClient("0x5Ec92458ACD047f3B583E09C243a480Ef54A68D4", self._config["grpc_endpoint"])
        self._client.connect()
        self._client.locate_peer_id("0x5Ec92458ACD047f3B583E09C243a480Ef54A68D4")
        print("RifCommsNode init on grpc endpoint: {}".format(self._config["grpc_endpoint"]))

    def start(self, raiden_service: RaidenService, message_handler: MessageHandler, prev_auth_data: str):
        raise NotImplementedError

    def stop(self):
        raise NotImplementedError

    def send_message(self, message: Message, recipient: Address):
        raise NotImplementedError

    def start_health_check(self, address: Address):
        raise NotImplementedError

    def whitelist(self, address: Address):
        raise NotImplementedError

    def link_exception(self, callback: Any):
        raise NotImplementedError

    def join(self, timeout=None):
        raise NotImplementedError

    def _run(self, *args: Any, **kwargs: Any) -> None:
        raise NotImplementedError


class RifCommsLightClientNode(RifCommsNode):

    def __init__(self, address: Address, config: dict, auth_params: dict):
        RifCommsNode.__init__(self, address, config)
