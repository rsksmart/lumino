from typing import Any, List, Dict, NewType

import gevent
import structlog
from gevent import Greenlet
from gevent.event import Event
from greenlet import GreenletExit

from raiden.message_handler import MessageHandler
from raiden.messages import Message
from raiden.raiden_service import RaidenService
from raiden.utils.runnable import Runnable
from raiden.utils import Address, pex
from transport.matrix.utils import _RetryQueue
from transport.node import Node as TransportNode
from transport.rif_comms.client import RifCommsClient
from eth_utils import to_checksum_address


_RoomID = NewType("_RoomID", str)
log = structlog.get_logger(__name__)

class RifCommsNode(TransportNode, Runnable):

    log = log

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

        self.log = log.bind(node_address=pex(self.address))



    def start(self, raiden_service: RaidenService, message_handler: MessageHandler, prev_auth_data: str):
        if not self._stop_event.ready():
            raise RuntimeError(f"{self!r} already started")
        self._stop_event.clear()
        self._raiden_service = raiden_service
        self._client.connect()
        self._client.get_peer_id(to_checksum_address(raiden_service.address)) # TODO remove when blocking grpc api bug solved

        # TODO matrix node here invokes inventory_rooms that sets the handle_message callback
        # TODO here we must also check for new messages as the matrix node does with   self._client.start_listener_thread()
        #         self._client.sync_thread.link_exception(self.on_error)
        #         self._client.sync_thread.link_value(on_success)
        #         self.greenlets = [self._client.sync_thread]
        for message_queue in self._address_to_message_queue.values():
            if not message_queue:
                self.log.debug("Starting message_queue", message_queue=message_queue)
                message_queue.start()
        self.log.debug("RIF Comms Node started", config=self._config)
        Runnable.start(self)


    def __repr__(self):
        if self._raiden_service is not None:
            node = f" node:{pex(self._raiden_service.address)}"
        else:
            node = ""

        return f"<{self.__class__.__name__}{node} id:{id(self)}>"


    def _run(self, *args: Any, **kwargs: Any) -> None:
        # TODO ActionUpdateTransportAuthData?
        # TODO which is the  Runnable main method, that perform wait on long-running subtasks ?"
        """ Runnable main method, perform wait on long-running subtasks """
        # dispatch auth data on first scheduling after start
        self.greenlet.name = f"RifCommsNode._run node:{pex(self._raiden_service.address)}"
        try:
            # waits on _stop_event.ready()
            # children crashes should throw an exception here
        except GreenletExit:  # killed without exception
            self._stop_event.set()
            gevent.killall(self.greenlets)  # kill children
            raise  # re-raise to keep killed status
        except Exception:
            self.stop()  # ensure cleanup and wait on subtasks
            raise

    def stop(self):
        """
        Try to gracefully stop the greenlet synchronously

        Stop isn't expected to re-raise greenlet _run exception
        (use self.greenlet.get() for that),
        but it should raise any stop-time exception

        Disconnects from RIF Communications node
        """
        if self._stop_event.ready():
            return
        self._stop_event.set()

        for message_queue in self._address_to_message_queue.values():
            if message_queue: # if message_queue.greenlet is not None
                message_queue.notify() # if we need to send something, this is the time

        # TODO we must stop the listener thread if present on this implementation
        # self._client.stop_listener_thread()  # stop sync_thread, wait client's greenlets

        # wait own greenlets, no need to get on them, exceptions should be raised in _run()
        gevent.wait(self.greenlets + [r.greenlet for r in self._address_to_message_queue.values()])

        # TODO we must end rif comms communication and grpc session

        self.log.debug("RIF Comms Node stopped", config=self._config)
        try:
            del self.log
        except AttributeError:
            # During shutdown the log attribute may have already been collected
            pass
        # parent may want to call get() after stop(), to ensure _run errors are re-raised
        # we don't call it here to avoid deadlock when self crashes and calls stop() on finally


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




class RifCommsLightClientNode(RifCommsNode):

    def __init__(self, address: Address, config: dict, auth_params: dict):
        RifCommsNode.__init__(self, address, config)
