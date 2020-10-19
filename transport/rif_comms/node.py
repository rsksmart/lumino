from typing import Any

from raiden.message_handler import MessageHandler
from raiden.raiden_service import RaidenService
from raiden.utils.typing import Address
from transport.message import Message
from transport.node import Node as TransportNode


class RifCommsNode(TransportNode):

    def __init__(self, address: Address, config: dict):
        TransportNode.__init__(self, address)

    def start(self, raiden_service: RaidenService, message_handler: MessageHandler, prev_auth_data: str):
        pass

    def stop(self):
        pass

    def send_message(self, message: Message, recipient: Address):
        pass

    def start_health_check(self, address: Address):
        pass

    def whitelist(self, address: Address):
        pass

    def link_exception(self, callback: Any):
        pass

    def join(self, timeout=None):
        pass


class RifCommsLightClientNode(RifCommsNode):

    def __init__(self, address: Address, config: dict):
        RifCommsNode.__init__(self, address, config)
