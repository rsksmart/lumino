from typing import Any

import structlog

from raiden.message_handler import MessageHandler
from raiden.messages import Message
from raiden.raiden_service import RaidenService
from raiden.utils.runnable import Runnable
from raiden.utils.typing import (
    Address,
)
from transport.node import Node as TransportNode

log = structlog.get_logger(__name__)


class RifCommsNode(TransportNode, Runnable):

    log = log

    def __init__(self, address: Address, config: dict):
        TransportNode.__init__(self, address)
        Runnable.__init__(self)
        self._config = config
        print("RifCommsNode init on grpc endpoint: {}".format(self._config["grpc_endpoint"]))

    def start(self, raiden_service: RaidenService, message_handler: MessageHandler, prev_auth_data: str):
        raise Exception("Not implemented")

    def stop(self):
        raise Exception("Not implemented")

    def send_message(self, message: Message, recipient: Address):
        raise Exception("Not implemented")

    def start_health_check(self, address: Address):
        raise Exception("Not implemented")

    def whitelist(self, address: Address):
        raise Exception("Not implemented")

    def link_exception(self, callback: Any):
        raise Exception("Not implemented")

    def join(self, timeout=None):
        raise Exception("Not implemented")

    def _run(self, *args: Any, **kwargs: Any) -> None:
        raise Exception("Not implemented")


class RifCommsLightClientNode(RifCommsNode):

    def __init__(self, address: Address, config: dict, auth_params: dict):
        RifCommsNode.__init__(self, address, config)

    def start(self, raiden_service: RaidenService, message_handler: MessageHandler, prev_auth_data: str):
        raise Exception("Not implemented")

    def stop(self):
        raise Exception("Not implemented")

    def send_message(self, message: Message, recipient: Address):
        raise Exception("Not implemented")

    def start_health_check(self, address: Address):
        raise Exception("Not implemented")

    def whitelist(self, address: Address):
        raise Exception("Not implemented")

    def link_exception(self, callback: Any):
        raise Exception("Not implemented")

    def join(self, timeout=None):
        raise Exception("Not implemented")

    def _run(self, *args: Any, **kwargs: Any) -> None:
        raise Exception("Not implemented")





