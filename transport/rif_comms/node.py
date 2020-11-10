from typing import Any, List, Dict

from gevent import Greenlet
from gevent.event import Event

from raiden.message_handler import MessageHandler
from raiden.messages import Message
from raiden.raiden_service import RaidenService
from raiden.utils.runnable import Runnable
from raiden.utils.typing import Address
from transport.matrix.utils import _RetryQueue
from transport.node import Node as TransportNode
from transport.rif_comms.client import RifCommsClient
from eth_utils import to_checksum_address


class RifCommsNode(TransportNode, Runnable):

    def __init__(self, address: Address, config: dict):
        TransportNode.__init__(self, address)
        Runnable.__init__(self)
        self._config = config
        self._raiden_service: RaidenService = None

        self._client = RifCommsClient(to_checksum_address(address), self._config["grpc_endpoint"])
        print("RifCommsNode init on grpc endpoint: {}".format(self._config["grpc_endpoint"]))

        self._greenlets: List[Greenlet] = list()# TODO why we need this? how it works the _spawn
        self._address_to_message_queue: Dict[Address, _RetryQueue] = dict() # TODO RetryQueue is on matrix package

        self._stop_event = Event() # TODO used on handle message and another points, pending review
        self._stop_event.set()

    def start(self, raiden_service: RaidenService, message_handler: MessageHandler, prev_auth_data: str):
        if not self._stop_event.ready():
            raise RuntimeError(f"{self!r} already started")
        self._stop_event.clear()
        self._raiden_service = raiden_service
        self._client.connect()
        self._client.get_peer_id(to_checksum_address(raiden_service.address)) # TODO remove when blocking grpc api bug solved

        # TODO matrix node here invokes inventory_rooms that sets the handle_message callback

        for message_queue in self._address_to_message_queue.values():
            if not message_queue:
                self.log.debug("Starting message_queue", message_queue=message_queue)
                message_queue.start()

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
