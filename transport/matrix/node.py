import json
from collections import defaultdict
from typing import Optional, Iterable, List, Dict, Tuple, Callable, Union, cast, Any, Set, NewType
from urllib.parse import urlparse

import gevent
import structlog
from eth_utils import to_normalized_address, is_binary_address, to_checksum_address, to_canonical_address
from gevent._semaphore import Semaphore
from gevent.event import Event
from gevent.queue import JoinableQueue
from matrix_client.errors import MatrixRequestError
from matrix_client.user import User
from raiden.constants import DISCOVERY_DEFAULT_ROOM
from raiden.exceptions import InvalidAddress, UnknownAddress, UnknownTokenAddress
from raiden.message_handler import MessageHandler
from raiden.messages import Message, Ping, Pong, SignedRetrieableMessage, SignedMessage, Delivered, Processed, ToDevice
from raiden.raiden_service import RaidenService
from raiden.transfer.identifiers import QueueIdentifier
from raiden.transfer.mediated_transfer.events import CHANNEL_IDENTIFIER_GLOBAL_QUEUE
from raiden.transfer.state import NODE_NETWORK_REACHABLE, NODE_NETWORK_UNKNOWN, \
    NODE_NETWORK_UNREACHABLE
from raiden.transfer.state_change import ActionUpdateTransportAuthData, ActionChangeNodeNetworkState
from raiden.utils import Address, pex
from raiden.utils.runnable import Runnable
from raiden.utils.typing import ChainID, AddressHex
from transport.matrix.client import Room, GMatrixClient
from transport.matrix.utils import get_available_servers_from_config, make_client, get_server_url, UserAddressManager, \
    login_or_register, make_room_alias, join_global_room, UserPresence, validate_userid_signature, JOIN_RETRIES, \
    AddressReachability, login_or_register_light_client
from transport.message import Message as TransportMessage
from transport.node import Node as TransportNode
from transport.udp import utils as udp_utils
from transport.utils import MessageQueue, validate_and_parse_messages

_RoomID = NewType("_RoomID", str)
log = structlog.get_logger(__name__)


class MatrixNode(TransportNode):
    _room_prefix = "raiden"
    _room_sep = "_"
    _log = log

    def __init__(self, address: Address, config: dict):
        TransportNode.__init__(self, address)

        self._config = config
        self._raiden_service: Optional[RaidenService] = None

        current_server_name = config.get("current_server_name")
        available_servers = get_available_servers_from_config(self._config)

        def _http_retry_delay() -> Iterable[float]:
            # below constants are defined in raiden.app.App.DEFAULT_CONFIG
            return udp_utils.timeout_exponential_backoff(
                config["retries_before_backoff"],
                config["retry_interval"] / 5,
                config["retry_interval"],
            )

        self._client: GMatrixClient = make_client(
            [get_server_url(current_server_name, available_servers)] if current_server_name else available_servers,
            http_pool_maxsize=4,
            http_retry_timeout=40,
            http_retry_delay=_http_retry_delay,
        )

        self._server_url = self._client.api.base_url
        self._server_name = config.get("server_name", urlparse(self._server_url).netloc)

        self.greenlets: List[gevent.Greenlet] = list()

        self._address_to_retrier: Dict[Address, MessageQueue] = dict()

        self._global_rooms: Dict[str, Optional[Room]] = dict()
        self._global_send_queue: JoinableQueue[Tuple[str, Message]] = JoinableQueue()

        self._started = False

        self._global_send_event = Event()
        self._prioritize_global_messages = True

        self._address_mgr: UserAddressManager = UserAddressManager(
            client=self._client,
            get_user_callable=self._get_user,
            address_reachability_changed_callback=self._address_reachability_changed,
            user_presence_changed_callback=self._user_presence_changed,
            stop_event=self.stop_event,
        )

        self._client.add_invite_listener(self._handle_invite)
        self._client.add_listener(self._handle_to_device_message, event_type="to_device")

        self._health_lock = Semaphore()
        self._getroom_lock = Semaphore()
        self._account_data_lock = Semaphore()

        self._message_handler: Optional[MessageHandler] = None

    def enqueue_global_messages(self):
        if self._prioritize_global_messages:
            self._global_send_queue.join()

    @property
    def raiden_service(self) -> 'RaidenService':
        return self._raiden_service

    @property
    def config(self) -> {}:
        return self._config

    @property
    def log(self):
        return self._log

    def start_greenlet_for_light_client(self):
        Runnable.start(self)

    def __repr__(self):
        if self._raiden_service is not None:
            node = f" node:{pex(self._raiden_service.address)}"
        else:
            node = ""

        return f"<{self.__class__.__name__}{node} id:{id(self)}>"

    def start(  # type: ignore
        self, raiden_service: RaidenService, message_handler: MessageHandler, prev_auth_data: str
    ):
        if not self.stop_event.ready():
            raise RuntimeError(f"{self!r} already started")
        self.stop_event.clear()
        self._raiden_service = raiden_service
        self._message_handler = message_handler

        prev_user_id: Optional[str]
        prev_access_token: Optional[str]
        if prev_auth_data and prev_auth_data.count("/") == 1:
            prev_user_id, _, prev_access_token = prev_auth_data.partition("/")
        else:
            prev_user_id = prev_access_token = None

        login_or_register(
            client=self._client,
            signer=self._raiden_service.signer,
            prev_user_id=prev_user_id,
            prev_access_token=prev_access_token
        )

        self._log = log.bind(current_user=self._user_id, node=pex(self._raiden_service.address))

        self.log.debug("Start: handle thread", handle_thread=self._client._handle_thread)
        if self._client._handle_thread:
            # wait on _handle_thread for initial sync
            # this is needed so the rooms are populated before we _inventory_rooms
            self._client._handle_thread.get()

        for suffix in self._config["global_rooms"]:
            room_name = make_room_alias(self.network_id, suffix)  # e.g. raiden_ropsten_discovery
            room = join_global_room(
                self._client, room_name, self._config.get("available_servers") or ()
            )
            self._global_rooms[room_name] = room

        self._inventory_rooms()

        def on_success(greenlet):
            if greenlet in self.greenlets:
                self.greenlets.remove(greenlet)

        self._client.start_listener_thread()
        self._client.sync_thread.link_exception(self.on_error)
        self._client.sync_thread.link_value(on_success)
        self.greenlets = [self._client.sync_thread]

        self._client.set_presence_state(UserPresence.ONLINE.value)

        # (re)start any _RetryQueue which was initialized before start
        for retrier in self._address_to_retrier.values():
            if not retrier.greenlet:
                self.log.debug("Starting retrier", retrier=retrier)
                retrier.start()

        self.log.debug("Matrix started", config=self._config)
        Runnable.start(self)  # start greenlet
        self._started = True

    def _run(self):
        """ Runnable main method, perform wait on long-running subtasks """
        # dispatch auth data on first scheduling after start
        state_change = ActionUpdateTransportAuthData(f"{self._user_id}/{self._client.api.token}",
                                                     self._raiden_service.address)
        self.greenlet.name = f"MatrixTransport._run node:{pex(self._raiden_service.address)}"
        self._raiden_service.handle_and_track_state_change(state_change)
        try:
            # waits on stop_event.ready()
            self._global_send_worker()
            # children crashes should throw an exception here
        except gevent.GreenletExit:  # killed without exception
            self.stop_event.set()
            gevent.killall(self.greenlets)  # kill children
            raise  # re-raise to keep killed status
        except Exception:
            self.stop()  # ensure cleanup and wait on subtasks
            raise

    def stop(self):
        """ Try to gracefully stop the greenlet synchronously

        Stop isn't expected to re-raise greenlet _run exception
        (use self.greenlet.get() for that),
        but it should raise any stop-time exception """
        if self.stop_event.ready():
            return
        self.stop_event.set()
        self._global_send_event.set()

        for retrier in self._address_to_retrier.values():
            if retrier:
                retrier.notify()

        self._client.set_presence_state(UserPresence.OFFLINE.value)

        self._client.stop_listener_thread()  # stop sync_thread, wait client's greenlets
        # wait own greenlets, no need to get on them, exceptions should be raised in _run()
        gevent.wait(self.greenlets + [r.greenlet for r in self._address_to_retrier.values()])

        # Ensure keep-alive http connections are closed
        self._client.api.session.close()

        self.log.debug("Matrix stopped", config=self._config)
        try:
            del self._log
        except AttributeError:
            # During shutdown the log attribute may have already been collected
            pass
        # parent may want to call get() after stop(), to ensure _run errors are re-raised
        # we don't call it here to avoid deadlock when self crashes and calls stop() on finally

    def _spawn(self, func: Callable, *args, **kwargs) -> gevent.Greenlet:
        """ Spawn a sub-task and ensures an error on it crashes self/main greenlet """

        def on_success(greenlet):
            if greenlet in self.greenlets:
                self.greenlets.remove(greenlet)

        greenlet = gevent.spawn(func, *args, **kwargs)
        greenlet.link_exception(self.on_error)
        greenlet.link_value(on_success)
        self.greenlets.append(greenlet)
        return greenlet

    def whitelist(self, address: Address):
        """Whitelist peer address to receive communications from

        This may be called before transport is started, to ensure events generated during
        start are handled properly.
        """
        self.log.debug("Whitelist", address=to_normalized_address(address))
        self._address_mgr.add_address(address)

    def start_health_check(self, node_address):
        """Start healthcheck (status monitoring) for a peer

        It also whitelists the address to answer invites and listen for messages
        """
        if self.stop_event.ready():
            return

        with self._health_lock:
            if self._address_mgr.is_address_known(node_address):
                return  # already healthchecked

            node_address_hex = to_normalized_address(node_address)
            self.log.debug("Healthcheck", peer_address=node_address_hex)

            candidates = [
                self._get_user(user)
                for user in self._client.search_user_directory(node_address_hex)
            ]
            user_ids = {
                user.user_id
                for user in candidates
                if validate_userid_signature(user) == node_address
            }
            self.whitelist(node_address)
            self._address_mgr.add_userids_for_address(node_address, user_ids)

            # Ensure network state is updated in case we already know about the user presences
            # representing the target node
            self._address_mgr.refresh_address_presence(node_address)

    def enqueue_message(self, message: TransportMessage, recipient: Address):
        """Queue the message for sending to recipient in the queue_identifier

        It may be called before transport is started, to initialize message queues
        The actual sending is started only when the transport is started
        """
        raiden_message, queue_identifier = TransportMessage.unwrap(message)

        # even if transport is not started, can run to enqueue messages to send when it starts
        if not is_binary_address(recipient):
            raise ValueError("Invalid address {}".format(pex(recipient)))

        # These are not protocol messages, but transport specific messages
        if isinstance(raiden_message, (Ping, Pong)):
            raise ValueError(
                "Do not use enqueue_message for {} messages".format(raiden_message.__class__.__name__)
            )

        self.log.info(
            "Enqueue message",
            recipient=pex(recipient),
            message=raiden_message,
            queue_identifier=queue_identifier,
        )

        self._send_with_retry(queue_identifier, raiden_message)

    def send_global(self, room: str, message: Message) -> None:
        """Sends a message to one of the global rooms

        These rooms aren't being listened on and therefore no reply could be heard, so these
        messages are sent in a send-and-forget async way.
        The actual room name is composed from the suffix given as parameter and chain name or id
        e.g.: raiden_ropsten_discovery
        Params:
            room: name suffix as passed in config['global_rooms'] list
            message: Message instance to be serialized and sent
        """
        self._global_send_queue.put((room, message))
        self._global_send_event.set()

    def _global_send_worker(self):
        def _send_global(room_name, serialized_message):
            if not any(suffix in room_name for suffix in self._config["global_rooms"]):
                raise RuntimeError(
                    f'Send global called on non-global room "{room_name}". '
                    f'Known global rooms: {self._config["global_rooms"]}.'
                )
            room_name = make_room_alias(self.network_id, room_name)
            if room_name not in self._global_rooms:
                room = join_global_room(
                    self._client, room_name, self._config.get("available_servers") or ()
                )
                self._global_rooms[room_name] = room

            assert self._global_rooms.get(room_name), f"Unknown global room: {room_name!r}"

            room = self._global_rooms[room_name]
            self.log.debug(
                "Send global",
                room_name=room_name,
                room=room,
                data=serialized_message.replace("\n", "\\n"),
            )
            room.send_text(serialized_message)

        while not self.stop_event.ready():
            self._global_send_event.clear()
            messages: Dict[str, List[Message]] = defaultdict(list)
            while self._global_send_queue.qsize() > 0:
                room_name, message = self._global_send_queue.get()
                messages[room_name].append(message)
            for room_name, messages_for_room in messages.items():
                message_text = "\n".join(
                    json.dumps(message.to_dict()) for message in messages_for_room
                )
                _send_global(room_name, message_text)
                self._global_send_queue.task_done()

            # Stop prioritizing global messages after initial queue has been emptied
            self._prioritize_global_messages = False
            self._global_send_event.wait(self._config["retry_interval"])

    @property
    def _user_id(self) -> Optional[str]:
        return getattr(self, "_client", None) and getattr(self._client, "user_id", None)

    @property
    def network_id(self) -> ChainID:
        assert self._raiden_service is not None
        return ChainID(self._raiden_service.chain.network_id)

    @property
    def _private_rooms(self) -> bool:
        return bool(self._config.get("private_rooms"))

    def _inventory_rooms(self):
        self.log.debug("Inventory rooms", rooms=self._client.rooms)
        for room in self._client.rooms.values():
            room_aliases = set(room.aliases)
            if room.canonical_alias:
                room_aliases.add(room.canonical_alias)
            room_alias_is_global = any(
                global_alias in room_alias
                for global_alias in self._config["global_rooms"]
                for room_alias in room_aliases
            )
            if room_alias_is_global:
                continue
            # we add listener for all valid rooms, _handle_message should ignore them
            # if msg sender isn't whitelisted yet
            if not room.listeners:
                room.add_listener(self._handle_message, "m.room.message")
            self.log.debug(
                "Room", room=room, aliases=room.aliases, members=room.get_joined_members()
            )

    def _handle_invite(self, room_id: _RoomID, state: dict):
        """ Join rooms invited by whitelisted partners """
        if self.stop_event.ready():
            return

        self.log.debug("Got invite", room_id=room_id)
        invite_events = [
            event
            for event in state["events"]
            if event["type"] == "m.room.member"
               and event["content"].get("membership") == "invite"
               and event["state_key"] == self._user_id
        ]
        if not invite_events:
            self.log.debug("Invite: no invite event found", room_id=room_id)
            return  # there should always be one and only one invite membership event for us
        invite_event = invite_events[0]
        sender = invite_event["sender"]

        sender_join_events = [
            event
            for event in state["events"]
            if event["type"] == "m.room.member"
               and event["content"].get("membership") == "join"
               and event["state_key"] == sender
        ]
        if not sender_join_events:
            self.log.debug("Invite: no sender join event", room_id=room_id)
            return  # there should always be one and only one join membership event for the sender
        sender_join_event = sender_join_events[0]

        user = self._get_user(sender)
        user.displayname = sender_join_event["content"].get("displayname") or user.displayname
        peer_address = validate_userid_signature(user)
        if not peer_address:
            self.log.debug(
                "Got invited to a room by invalid signed user - ignoring",
                room_id=room_id,
                user=user,
            )
            return

        if not self._address_mgr.is_address_known(peer_address):
            self.log.debug(
                "Got invited by a non-whitelisted user - ignoring", room_id=room_id, user=user
            )
            return

        join_rules_events = [
            event for event in state["events"] if event["type"] == "m.room.join_rules"
        ]

        # room privacy as seen from the event
        private_room: bool = False
        if join_rules_events:
            join_rules_event = join_rules_events[0]
            private_room = join_rules_event["content"].get("join_rule") == "invite"

        # we join room and _set_room_id_for_address despite room privacy and requirements,
        # _get_room_ids_for_address will take care of returning only matching rooms and
        # _leave_unused_rooms will clear it in the future, if and when needed
        room: Optional[Room] = None
        last_ex: Optional[Exception] = None
        retry_interval = 0.1
        for _ in range(JOIN_RETRIES):
            try:
                room = self._client.join_room(room_id)
            except MatrixRequestError as e:
                last_ex = e
                if self.stop_event.wait(retry_interval):
                    break
                retry_interval = retry_interval * 2
            else:
                break
        else:
            assert last_ex is not None
            raise last_ex  # re-raise if couldn't succeed in retries

        assert room is not None, f"joining room {room} failed"

        if not room.listeners:
            room.add_listener(self._handle_message, "m.room.message")

        # room state may not populated yet, so we populate 'invite_only' from event
        room.invite_only = private_room

        self._set_room_id_for_address(address=peer_address, room_id=room_id)

        self.log.debug(
            "Joined from invite",
            room_id=room_id,
            aliases=room.aliases,
            peer=to_checksum_address(peer_address),
        )

    def _handle_message(self, room, event) -> bool:
        """ Handle text messages sent to listening rooms """
        if (
            event["type"] != "m.room.message"
            or event["content"]["msgtype"] != "m.text"
            or self.stop_event.ready()
        ):
            # Ignore non-messages and non-text messages
            return False

        sender_id = event["sender"]

        if sender_id == self._user_id:
            # Ignore our own messages
            return False

        user = self._get_user(sender_id)
        peer_address = validate_userid_signature(user)
        if not peer_address:
            self.log.debug(
                "Message from invalid user displayName signature",
                peer_user=user.user_id,
                room=room,
            )
            return False

        # # don't proceed if user isn't whitelisted (yet)
        # if not self._address_mgr.is_address_known(peer_address):
        #     # user not whitelisted
        #     self.log.debug(
        #         "Message from non-whitelisted peer - ignoring",
        #         sender=user,
        #         sender_address=pex(peer_address),
        #         room=room,
        #     )
        #     return False

        # rooms we created and invited user, or were invited specifically by them
        room_ids = self._get_room_ids_for_address(peer_address)

        # TODO: Remove clause after `and` and check if things still don't hang
        if room.room_id not in room_ids and (self._private_rooms and not room.invite_only):
            # this should not happen, but is not fatal, as we may not know user yet
            if self._private_rooms and not room.invite_only:
                reason = "required private room, but received message in a public"
            else:
                reason = "unknown room for user"
            self.log.debug(
                "Ignoring invalid message",
                peer_user=user.user_id,
                peer_address=pex(peer_address),
                room=room,
                expected_room_ids=room_ids,
                reason=reason,
            )
            return False

        # TODO: With the condition in the TODO above restored this one won't have an effect, check
        #       if it can be removed after the above is solved
        if not room_ids or room.room_id != room_ids[0]:
            if self._is_room_global(room):
                # This must not happen. Nodes must not listen on global rooms.
                raise RuntimeError(f"Received message in global room {room.aliases}.")
            self.log.debug(
                "Received message triggered new comms room for peer",
                peer_user=user.user_id,
                peer_address=pex(peer_address),
                known_user_rooms=room_ids,
                room=room,
            )
            self._set_room_id_for_address(peer_address, room.room_id)

        is_peer_reachable = self._address_mgr.get_address_reachability(peer_address) is (
            AddressReachability.REACHABLE
        )
        if not is_peer_reachable:
            self.log.debug("Forcing presence update", peer_address=peer_address, user_id=sender_id)
            self._address_mgr.force_user_presence(user, UserPresence.ONLINE)
            self._address_mgr.refresh_address_presence(peer_address)

        messages = validate_and_parse_messages(event["content"]["body"], peer_address)

        if not messages:
            return False

        self.log.info(
            "Incoming messages",
            messages=messages,
            sender=pex(peer_address),
            sender_user=user,
            room=room,
        )

        for message in messages:
            if not isinstance(message, (SignedRetrieableMessage, SignedMessage)):
                self.log.warning("Received invalid message", message=message)
            if isinstance(message, Delivered):
                self._receive_delivered(message)
            elif isinstance(message, Processed):
                self._receive_message(message)
            else:
                assert isinstance(message, SignedRetrieableMessage)
                self._receive_message(message)

        return True

    def _receive_delivered(self, delivered: Delivered):
        self.log.info(
            "Delivered message received", sender=pex(delivered.sender), message=delivered
        )

        assert self._raiden_service is not None
        self._raiden_service.on_message(delivered)

    def _receive_message(self, message: Union[SignedRetrieableMessage, Processed]):
        print("---- Matrix Received Message HUB Transport" + str(message))
        assert self._raiden_service is not None
        self.log.info(
            "Message received",
            node=pex(self._raiden_service.address),
            message=message,
            sender=pex(message.sender),
        )

        try:
            # TODO: Maybe replace with Matrix read receipts.
            #       Unfortunately those work on an 'up to' basis, not on individual messages
            #       which means that message order is important which isn't guaranteed between
            #       federated servers.
            #       See: https://matrix.org/docs/spec/client_server/r0.3.0.html#id57
            delivered_message = Delivered(delivered_message_identifier=message.message_identifier)
            self._raiden_service.sign(delivered_message)

            queue_identifier = QueueIdentifier(
                recipient=message.sender, channel_identifier=CHANNEL_IDENTIFIER_GLOBAL_QUEUE
            )
            self.enqueue_message(*TransportMessage.wrap(queue_identifier, delivered_message))
            self._raiden_service.on_message(message)

        except (InvalidAddress, UnknownAddress, UnknownTokenAddress):
            self.log.warning("Exception while processing message", exc_info=True)
            return

    def _receive_to_device(self, to_device: ToDevice):
        self.log.debug(
            "ToDevice message received", sender=pex(to_device.sender), message=to_device
        )

    def _get_retrier(self, recipient: Address) -> MessageQueue:
        """ Construct and return a MessageQueue for recipient """
        if recipient not in self._address_to_retrier:
            retrier = MessageQueue(transport_node=self, recipient=recipient)
            self._address_to_retrier[recipient] = retrier
            # Always start the _RetryQueue, otherwise `stop` will block forever
            # waiting for the corresponding gevent.Greenlet to complete. This
            # has no negative side-effects if the transport has stopped because
            # the retrier itself checks the transport running state.
            retrier.start()
        return self._address_to_retrier[recipient]

    def _send_with_retry(self, queue_identifier: QueueIdentifier, message: Message):
        retrier = self._get_retrier(queue_identifier.recipient)
        retrier.enqueue(queue_identifier=queue_identifier, message=message)

    def send_message(self, payload: str, recipient: Address):
        with self._getroom_lock:
            room = self._get_room_for_address(recipient)
        if not room:
            self.log.error(
                "No room for recipient", recipient=to_normalized_address(recipient)
            )
            return
        self.log.debug(
            "Send raw", recipient=pex(recipient), room=room, payload=payload.replace("\n", "\\n")
        )
        print("---->> Matrix Send Message " + payload)

        room.send_text(payload)

    def _get_room_for_address(self, address: Address, allow_missing_peers=False) -> Optional[Room]:
        if self.stop_event.ready():
            return None
        address_hex = to_normalized_address(address)

        # filter_private is done in _get_room_ids_for_address
        room_ids = self._get_room_ids_for_address(address)
        if room_ids:  # if we know any room for this user, use the first one
            # This loop is used to ignore any global rooms that may have 'polluted' the
            # user's room cache due to bug #3765
            # Can be removed after the next upgrade that switches to a new TokenNetworkRegistry
            while room_ids:
                room_id = room_ids.pop(0)
                room = self._client.rooms[room_id]
                if not self._is_room_global(room):
                    self.log.warning("Existing room", room=room, members=room.get_joined_members())
                    return room
                self.log.warning("Ignoring global room for peer", room=room, peer=address_hex)

        assert self._raiden_service is not None
        address_pair = sorted(
            [to_normalized_address(address) for address in [address, self._raiden_service.address]]
        )
        room_name = make_room_alias(self.network_id, *address_pair)

        # no room with expected name => create one and invite peer
        peer_candidates = [
            self._get_user(user) for user in self._client.search_user_directory(address_hex)
        ]

        # filter peer_candidates
        peers = [user for user in peer_candidates if validate_userid_signature(user) == address]
        if not peers and not allow_missing_peers:
            self.log.error("No valid peer found", peer_address=address_hex)
            return None

        if self._private_rooms:
            room = self._get_private_room(invitees=peers)
        else:
            room = self._get_public_room(room_name, invitees=peers)

        peer_ids = self._address_mgr.get_userids_for_address(address)
        member_ids = {member.user_id for member in room.get_joined_members(force_resync=True)}
        room_is_empty = not bool(peer_ids & member_ids)
        if room_is_empty:
            last_ex: Optional[Exception] = None
            retry_interval = 0.1
            self.log.debug("Waiting for peer to join from invite", peer_address=address_hex)
            for _ in range(JOIN_RETRIES):
                try:
                    member_ids = {member.user_id for member in room.get_joined_members()}
                except MatrixRequestError as e:
                    last_ex = e
                room_is_empty = not bool(peer_ids & member_ids)
                if room_is_empty or last_ex:
                    if self.stop_event.wait(retry_interval):
                        break
                    retry_interval = retry_interval * 2
                else:
                    break

            if room_is_empty or last_ex:
                if last_ex:
                    raise last_ex  # re-raise if couldn't succeed in retries
                else:
                    # Inform the client, that currently no one listens:
                    self.log.error(
                        "Peer has not joined from invite yet, should join eventually",
                        peer_address=address_hex,
                    )

        self._address_mgr.add_userids_for_address(address, {user.user_id for user in peers})
        self._set_room_id_for_address(address, room.room_id)

        if not room.listeners:
            room.add_listener(self._handle_message, "m.room.message")

        self.log.debug("Channel room", peer_address=to_normalized_address(address), room=room)
        return room

    def _is_room_global(self, room):
        return any(
            suffix in room_alias
            for suffix in self._config["global_rooms"]
            for room_alias in room.aliases
        )

    def _get_private_room(self, invitees: List[User]):
        """ Create an anonymous, private room and invite peers """
        return self._client.create_room(
            None, invitees=[user.user_id for user in invitees], is_public=False
        )

    def _get_public_room(self, room_name, invitees: List[User]):
        """ Obtain a public, canonically named (if possible) room and invite peers """
        room_name_full = f"#{room_name}:{self._server_name}"
        invitees_uids = [user.user_id for user in invitees]

        for _ in range(JOIN_RETRIES):
            # try joining room
            try:
                room = self._client.join_room(room_name_full)
            except MatrixRequestError as error:
                if error.code == 404:
                    self.log.debug(
                        f"No room for peer, trying to create",
                        room_name=room_name_full,
                        error=error,
                    )
                else:
                    self.log.debug(
                        f"Error joining room",
                        room_name=room_name,
                        error=error.content,
                        error_code=error.code,
                    )
            else:
                # Invite users to existing room
                member_ids = {user.user_id for user in room.get_joined_members(force_resync=True)}
                users_to_invite = set(invitees_uids) - member_ids
                self.log.debug("Inviting users", room=room, invitee_ids=users_to_invite)
                for invitee_id in users_to_invite:
                    room.invite_user(invitee_id)
                self.log.debug("Room joined successfully", room=room)
                break

            # if can't, try creating it
            try:
                room = self._client.create_room(room_name, invitees=invitees_uids, is_public=True)
            except MatrixRequestError as error:
                if error.code == 409:
                    msg = (
                        "Error creating room, "
                        "seems to have been created by peer meanwhile, retrying."
                    )
                else:
                    msg = "Error creating room, retrying."

                self.log.debug(
                    msg, room_name=room_name, error=error.content, error_code=error.code
                )
            else:
                self.log.debug("Room created successfully", room=room, invitees=invitees)
                break
        else:
            # if can't join nor create, create an unnamed one
            room = self._client.create_room(None, invitees=invitees_uids, is_public=True)
            self.log.warning(
                "Could not create nor join a named room. Successfuly created an unnamed one",
                room=room,
                invitees=invitees,
            )

        return room

    def _user_presence_changed(self, user: User, _presence: UserPresence):
        # maybe inviting user used to also possibly invite user's from presence changes
        assert self._raiden_service is not None  # make mypy happy
        greenlet = self._spawn(self._maybe_invite_user, user)
        greenlet.name = f"invite node:{pex(self._raiden_service.address)} user:{user}"

    def _address_reachability_changed(self, address: Address, reachability: AddressReachability):
        if reachability is AddressReachability.REACHABLE:
            node_reachability = NODE_NETWORK_REACHABLE
            # _QueueRetry.notify when partner comes online
            retrier = self._address_to_retrier.get(address)
            if retrier:
                retrier.notify()
        elif reachability is AddressReachability.UNKNOWN:
            node_reachability = NODE_NETWORK_UNKNOWN
        elif reachability is AddressReachability.UNREACHABLE:
            node_reachability = NODE_NETWORK_UNREACHABLE
        else:
            raise TypeError(f'Unexpected reachability state "{reachability}".')

        assert self._raiden_service is not None  # make mypy happy
        state_change = ActionChangeNodeNetworkState(address, node_reachability)
        self._raiden_service.handle_and_track_state_change(state_change)

    def _maybe_invite_user(self, user: User):
        address = validate_userid_signature(user)
        if not address:
            return

        room_ids = self._get_room_ids_for_address(address)
        if not room_ids:
            return

        room = self._client.rooms[room_ids[0]]
        if not room._members:
            room.get_joined_members(force_resync=True)
        if user.user_id not in room._members:
            self.log.debug("Inviting", user=user, room=room)
            try:
                room.invite_user(user.user_id)
            except (json.JSONDecodeError, MatrixRequestError):
                self.log.warning(
                    "Exception inviting user, maybe their server is not healthy",
                    user=user,
                    room=room,
                    exc_info=True,
                )

    def _get_user(self, user: Union[User, str]) -> User:
        """Creates an User from an user_id, if none, or fetch a cached User

        As all users are supposed to be in discovery room, its members dict is used for caching"""
        user_id: str = getattr(user, "user_id", user)
        discovery_room = self._global_rooms.get(
            make_room_alias(self.network_id, DISCOVERY_DEFAULT_ROOM)
        )
        if discovery_room and user_id in discovery_room._members:
            duser = discovery_room._members[user_id]
            # if handed a User instance with displayname set, update the discovery room cache
            if getattr(user, "displayname", None):
                assert isinstance(user, User)
                duser.displayname = user.displayname
            user = duser
        elif not isinstance(user, User):
            user = self._client.get_user(user_id)
        return user

    def _set_room_id_for_address(self, address: Address, room_id: Optional[_RoomID] = None):
        """ Uses GMatrixClient.set_account_data to keep updated mapping of addresses->rooms

        If room_id is falsy, clean list of rooms. Else, push room_id to front of the list """

        assert not room_id or room_id in self._client.rooms, "Invalid room_id"
        address_hex: AddressHex = to_checksum_address(address)
        # filter_private=False to preserve public rooms on the list, even if we require privacy
        room_ids = self._get_room_ids_for_address(address, filter_private=False)

        with self._account_data_lock:
            # no need to deepcopy, we don't modify lists in-place
            # cast generic Dict[str, Any] to types we expect, to satisfy mypy, runtime no-op
            _address_to_room_ids = cast(
                Dict[AddressHex, List[_RoomID]],
                self._client.account_data.get("network.raiden.rooms", {}).copy(),
            )

            changed = False
            if not room_id:  # falsy room_id => clear list
                changed = address_hex in _address_to_room_ids
                _address_to_room_ids.pop(address_hex, None)
            else:
                # push to front
                room_ids = [room_id] + [r for r in room_ids if r != room_id]
                if room_ids != _address_to_room_ids.get(address_hex):
                    _address_to_room_ids[address_hex] = room_ids
                    changed = True

            if changed:
                # dict will be set at the end of _clean_unused_rooms
                self._leave_unused_rooms(_address_to_room_ids)

    def _get_room_ids_for_address(
        self, address: Address, filter_private: bool = None
    ) -> List[_RoomID]:
        """ Uses GMatrixClient.get_account_data to get updated mapping of address->rooms

        It'll filter only existing rooms.
        If filter_private=True, also filter out public rooms.
        If filter_private=None, filter according to self._private_rooms
        """
        address_hex: AddressHex = to_checksum_address(address)
        with self._account_data_lock:
            room_ids = self._client.account_data.get("network.raiden.rooms", {}).get(address_hex)
            self.log.debug("matrix get account data", room_ids=room_ids, for_address=address_hex)
            if not room_ids:  # None or empty
                room_ids = list()
            if not isinstance(room_ids, list):  # old version, single room
                room_ids = [room_ids]

            if filter_private is None:
                filter_private = self._private_rooms
            if not filter_private:
                # existing rooms
                room_ids = [room_id for room_id in room_ids if room_id in self._client.rooms]
            else:
                # existing and private rooms
                room_ids = [
                    room_id
                    for room_id in room_ids
                    if room_id in self._client.rooms and self._client.rooms[room_id].invite_only
                ]

            return room_ids

    def _leave_unused_rooms(self, _address_to_room_ids: Dict[AddressHex, List[_RoomID]]):
        """
        Checks for rooms we've joined and which partner isn't health-checked and leave.

        **MUST** be called from a context that holds the `_account_data_lock`.
        """
        _msg = "_leave_unused_rooms called without account data lock"
        assert self._account_data_lock.locked(), _msg

        # TODO: Remove the next five lines and check if transfers start hanging again
        self._client.set_account_data(
            "network.raiden.rooms",  # back from cast in _set_room_id_for_address
            cast(Dict[str, Any], _address_to_room_ids),
        )
        return

        # cache in a set all whitelisted addresses
        whitelisted_hex_addresses: Set[AddressHex] = {
            to_checksum_address(address) for address in self._address_mgr.known_addresses
        }

        keep_rooms: Set[_RoomID] = set()

        for address_hex, room_ids in list(_address_to_room_ids.items()):
            if not room_ids:  # None or empty
                room_ids = list()
            if not isinstance(room_ids, list):  # old version, single room
                room_ids = [room_ids]

            if address_hex not in whitelisted_hex_addresses:
                _address_to_room_ids.pop(address_hex)
                continue

            counters = [0, 0]  # public, private
            new_room_ids: List[_RoomID] = list()

            # limit to at most 2 public and 2 private rooms, preserving order
            for room_id in room_ids:
                if room_id not in self._client.rooms:
                    continue
                elif self._client.rooms[room_id].invite_only is None:
                    new_room_ids.append(room_id)  # not known, postpone cleaning
                elif counters[self._client.rooms[room_id].invite_only] < 2:
                    counters[self._client.rooms[room_id].invite_only] += 1
                    new_room_ids.append(room_id)  # not enough rooms of this type yet
                else:
                    continue  # enough rooms, leave and clean

            keep_rooms |= set(new_room_ids)
            if room_ids != new_room_ids:
                _address_to_room_ids[address_hex] = new_room_ids

        rooms: List[Tuple[_RoomID, Room]] = list(self._client.rooms.items())

        self.log.debug("Updated address room mapping", address_to_room_ids=_address_to_room_ids)
        self._client.set_account_data("network.raiden.rooms", _address_to_room_ids)

        def leave(room: Room):
            """A race between /leave and /sync may remove the room before
            del on _client.rooms key. Suppress it, as the end result is the same: no more room"""
            try:
                self.log.debug("Leaving unused room", room=room)
                return room.leave()
            except KeyError:
                return True

        for room_id, room in rooms:
            if room_id in {groom.room_id for groom in self._global_rooms.values() if groom}:
                # don't leave global room
                continue
            if room_id not in keep_rooms:
                greenlet = self._spawn(leave, room)
                greenlet.name = (
                    f"MatrixTransport.leave "
                    f"node:{pex(self._raiden_service.address)} "
                    f"user_id:{self._user_id}"
                )

    def send_to_device(self, address: Address, message: Message) -> None:
        """ Sends send-to-device events to a all known devices of a peer without retries. """
        user_ids = self._address_mgr.get_userids_for_address(address)

        data = {user_id: {"*": json.dumps(message.to_dict())} for user_id in user_ids}

        return self._client.api.send_to_device("m.to_device_message", data)

    def _handle_to_device_message(self, event):
        """
        Handles to_device_message sent to us.
        - validates peer_whitelisted
        - validates userid_signature
        Todo: Currently doesnt do anything but logging when a to device message is received.
        """
        sender_id = event["sender"]

        if (
            event["type"] != "m.to_device_message"
            or self.stop_event.ready()
            or sender_id == self._user_id
        ):
            # Ignore non-messages and our own messages
            return False

        user = self._get_user(sender_id)
        peer_address = validate_userid_signature(user)
        if not peer_address:
            self.log.debug(
                "To_device_message from invalid user displayName signature", peer_user=user.user_id
            )
            return False

        # don't proceed if user isn't whitelisted (yet)
        if not self._address_mgr.is_address_known(peer_address):
            # user not start_health_check'ed
            self.log.debug(
                "ToDevice Message from non-whitelisted peer - ignoring",
                sender=user,
                sender_address=pex(peer_address),
            )
            return False

        is_peer_reachable = self._address_mgr.get_address_reachability(peer_address) is (
            AddressReachability.REACHABLE
        )

        if not is_peer_reachable:
            self.log.debug("Forcing presence update", peer_address=peer_address, user_id=sender_id)
            self._address_mgr.force_user_presence(user, UserPresence.ONLINE)
            self._address_mgr.refresh_address_presence(peer_address)

        messages = validate_and_parse_messages(event["content"], peer_address)

        if not messages:
            return False

        self.log.debug(
            "Incoming ToDevice Messages",
            messages=messages,
            sender=pex(peer_address),
            sender_user=user,
        )

        for message in messages:
            if isinstance(message, ToDevice):
                self._receive_to_device(message)
            else:
                log.warning(
                    "Received Message is not of type ToDevice, invalid",
                    message=message,
                    peer_address=peer_address,
                )
                continue

        return True

    def link_exception(self, callback: Any):
        self.greenlet.link_exception(callback)

    def join(self, timeout=None):
        self.greenlet.join(timeout)


class MatrixLightClientNode(MatrixNode):

    def __init__(self, address: Address, config: dict, auth_params: dict):
        MatrixNode.__init__(self, address, config)
        self._encrypted_light_client_password_signature = auth_params["light_client_password"]
        self._encrypted_light_client_display_name_signature = auth_params["light_client_display_name"]
        self._encrypted_light_client_seed_for_retry_signature = auth_params["light_client_seed_retry"]

    def start(  # type: ignore
        self,
        raiden_service: RaidenService,
        message_handler: MessageHandler,
        prev_auth_data: str,

    ):
        if not self.stop_event.ready():
            raise RuntimeError(f"{self!r} already started")
        self.stop_event.clear()
        self._raiden_service = raiden_service
        self._message_handler = message_handler

        prev_user_id: Optional[str]
        prev_access_token: Optional[str]
        if prev_auth_data and prev_auth_data.count("/") == 1:
            prev_user_id, _, prev_access_token = prev_auth_data.partition("/")
        else:
            prev_user_id = prev_access_token = None

        login_or_register_light_client(
            client=self._client,
            prev_user_id=prev_user_id,
            prev_access_token=prev_access_token,
            encrypted_light_client_password_signature=self._encrypted_light_client_password_signature,
            encrypted_light_client_display_name_signature=self._encrypted_light_client_display_name_signature,
            encrypted_light_client_seed_for_retry_signature=self._encrypted_light_client_seed_for_retry_signature,
            private_key_hub=self._raiden_service.config["privatekey"].hex(),
            light_client_address=self.address
        )

        self._log = log.bind(current_user=self._user_id, node=pex(self._raiden_service.address))

        self.log.debug("Start: handle thread", handle_thread=self._client._handle_thread)
        if self._client._handle_thread:
            # wait on _handle_thread for initial sync
            # this is needed so the rooms are populated before we _inventory_rooms
            self._client._handle_thread.get()

        for suffix in self._config["global_rooms"]:
            room_name = make_room_alias(self.network_id, suffix)  # e.g. raiden_ropsten_discovery
            room = join_global_room(
                self._client, room_name, self._config.get("available_servers") or ()
            )
            self._global_rooms[room_name] = room

        self._inventory_rooms()

        def on_success(greenlet):
            if greenlet in self.greenlets:
                self.greenlets.remove(greenlet)

        self._client.start_listener_thread()
        self._client.sync_thread.link_exception(self.on_error)
        self._client.sync_thread.link_value(on_success)
        self.greenlets = [self._client.sync_thread]

        self._client.set_presence_state(UserPresence.ONLINE.value)

        # (re)start any _RetryQueue which was initialized before start
        for retrier in self._address_to_retrier.values():
            if not retrier:
                self.log.debug("Starting retrier", retrier=retrier)
                retrier.start()

        self.log.debug("Matrix started", config=self._config)
        MatrixNode.start_greenlet_for_light_client(self)
        self._started = True

    def _run(self):
        """ Runnable main method, perform wait on long-running subtasks """
        # dispatch auth data on first scheduling after start
        state_change = ActionUpdateTransportAuthData(f"{self._user_id}/{self._client.api.token}", self.address)
        self.greenlet.name = f"MatrixLightClientTransport._run light_client:{to_canonical_address(self.address)}"
        self._raiden_service.handle_and_track_state_change(state_change)
        try:
            # waits on stop_event.ready()
            self._global_send_worker()
            # children crashes should throw an exception here
        except gevent.GreenletExit:  # killed without exception
            self.stop_event.set()
            gevent.killall(self.greenlets)  # kill children
            raise  # re-raise to keep killed status
        except Exception:
            self.stop()  # ensure cleanup and wait on subtasks
            raise

    def send_message(self, payload: str, recipient: Address):
        with self._getroom_lock:
            room = self._get_room_for_address(recipient)
        if not room:
            self.log.error(
                "No room for recipient", recipient=to_normalized_address(recipient)
            )
            return
        self.log.debug(
            "Send raw", recipient=pex(recipient), room=room, payload=payload.replace("\n", "\\n")
        )
        print("---- Matrix Send Message " + payload)

        room.send_text(payload)

    def _get_room_for_address(self, address: Address, allow_missing_peers=False) -> Optional[Room]:
        if self.stop_event.ready():
            return None
        address_hex = to_normalized_address(address)
        assert address

        # filter_private is done in _get_room_ids_for_address
        room_ids = self._get_room_ids_for_address(address)
        if room_ids:  # if we know any room for this user, use the first one
            # This loop is used to ignore any global rooms that may have 'polluted' the
            # user's room cache due to bug #3765
            # Can be removed after the next upgrade that switches to a new TokenNetworkRegistry
            while room_ids:
                room_id = room_ids.pop(0)
                room = self._client.rooms[room_id]
                if not self._is_room_global(room):
                    self.log.warning("Existing room", room=room, members=room.get_joined_members())
                    return room
                self.log.warning("Ignoring global room for peer", room=room, peer=address_hex)

        assert self._raiden_service is not None
        address_pair = sorted(
            [to_normalized_address(address) for address in [address, to_canonical_address(self.address)]]
        )

        room_name = make_room_alias(self.network_id, *address_pair)

        # no room with expected name => create one and invite peer
        peer_candidates = [
            self._get_user(user) for user in self._client.search_user_directory(address_hex)
        ]

        # filter peer_candidates
        peers = [user for user in peer_candidates if validate_userid_signature(user) == address]
        if not peers and not allow_missing_peers:
            self.log.error("No valid peer found", peer_address=address_hex)
            return None

        if self._private_rooms:
            room = self._get_private_room(invitees=peers)
        else:
            room = self._get_public_room(room_name, invitees=peers)

        peer_ids = self._address_mgr.get_userids_for_address(address)
        member_ids = {member.user_id for member in room.get_joined_members(force_resync=True)}
        room_is_empty = not bool(peer_ids & member_ids)
        if room_is_empty:
            last_ex: Optional[Exception] = None
            retry_interval = 0.1
            self.log.debug("Waiting for peer to join from invite", peer_address=address_hex)
            for _ in range(JOIN_RETRIES):
                try:
                    member_ids = {member.user_id for member in room.get_joined_members()}
                except MatrixRequestError as e:
                    last_ex = e
                room_is_empty = not bool(peer_ids & member_ids)
                if room_is_empty or last_ex:
                    if self.stop_event.wait(retry_interval):
                        break
                    retry_interval = retry_interval * 2
                else:
                    break

            if room_is_empty or last_ex:
                if last_ex:
                    raise last_ex  # re-raise if couldn't succeed in retries
                else:
                    # Inform the client, that currently no one listens:
                    self.log.error(
                        "Peer has not joined from invite yet, should join eventually",
                        peer_address=address_hex,
                    )

        self._address_mgr.add_userids_for_address(address, {user.user_id for user in peers})
        self._set_room_id_for_address(address, room.room_id)

        if not room.listeners:
            room.add_listener(self._handle_message, "m.room.message")

        self.log.debug("Channel room", peer_address=to_normalized_address(address), room=room)
        return room

    def _get_public_room(self, room_name, invitees: List[User]):
        """ Obtain a public, canonically named (if possible) room and invite peers """
        room_name_full = f"#{room_name}:{self._server_name}"
        invitees_uids = [user.user_id for user in invitees]

        for _ in range(JOIN_RETRIES):
            # try joining room
            try:
                room = self._client.join_room(room_name_full)
            except MatrixRequestError as error:
                if error.code == 404:
                    self.log.debug(
                        f"No room for peer, trying to create",
                        room_name=room_name_full,
                        error=error,
                    )
                else:
                    self.log.debug(
                        f"Error joining room",
                        room_name=room_name,
                        error=error.content,
                        error_code=error.code,
                    )
            else:
                # Invite users to existing room
                member_ids = {user.user_id for user in room.get_joined_members(force_resync=True)}
                users_to_invite = set(invitees_uids) - member_ids
                self.log.debug("Inviting users", room=room, invitee_ids=users_to_invite)
                for invitee_id in users_to_invite:
                    room.invite_user(invitee_id)
                self.log.debug("Room joined successfully", room=room)
                break

            # if can't, try creating it
            try:
                room = self._client.create_room(room_name, invitees=invitees_uids, is_public=True)
            except MatrixRequestError as error:
                if error.code == 409:
                    msg = (
                        "Error creating room, "
                        "seems to have been created by peer meanwhile, retrying."
                    )
                else:
                    msg = "Error creating room, retrying."

                self.log.debug(
                    msg, room_name=room_name, error=error.content, error_code=error.code
                )
            else:
                self.log.debug("Room created successfully", room=room, invitees=invitees)
                break
        else:
            # if can't join nor create, create an unnamed one
            room = self._client.create_room(None, invitees=invitees_uids, is_public=True)
            self.log.warning(
                "Could not create nor join a named room. Successfuly created an unnamed one",
                room=room,
                invitees=invitees,
            )

        return room

    def _handle_message(self, room, event) -> bool:
        """ Handle text messages sent to listening rooms """
        if (
            event["type"] != "m.room.message"
            or event["content"]["msgtype"] != "m.text"
            or self.stop_event.ready()
        ):
            # Ignore non-messages and non-text messages
            return False

        sender_id = event["sender"]

        if sender_id == self._user_id:
            # Ignore our own messages
            return False

        user = self._get_user(sender_id)
        peer_address = validate_userid_signature(user)
        if not peer_address:
            self.log.debug(
                "Message from invalid user displayName signature",
                peer_user=user.user_id,
                room=room,
            )
            return False

        # # don't proceed if user isn't whitelisted (yet)
        # if not self._address_mgr.is_address_known(peer_address):
        #     # user not whitelisted
        #     self.log.debug(
        #         "Message from non-whitelisted peer - ignoring",
        #         sender=user,
        #         sender_address=pex(peer_address),
        #         room=room,
        #     )
        #     return False

        # rooms we created and invited user, or were invited specifically by them
        room_ids = self._get_room_ids_for_address(peer_address)

        # TODO: Remove clause after `and` and check if things still don't hang
        if room.room_id not in room_ids and (self._private_rooms and not room.invite_only):
            # this should not happen, but is not fatal, as we may not know user yet
            if self._private_rooms and not room.invite_only:
                reason = "required private room, but received message in a public"
            else:
                reason = "unknown room for user"
            self.log.debug(
                "Ignoring invalid message",
                peer_user=user.user_id,
                peer_address=pex(peer_address),
                room=room,
                expected_room_ids=room_ids,
                reason=reason,
            )
            return False

        # TODO: With the condition in the TODO above restored this one won't have an effect, check
        #       if it can be removed after the above is solved
        if not room_ids or room.room_id != room_ids[0]:
            if self._is_room_global(room):
                # This must not happen. Nodes must not listen on global rooms.
                raise RuntimeError(f"Received message in global room {room.aliases}.")
            self.log.debug(
                "Received message triggered new comms room for peer",
                peer_user=user.user_id,
                peer_address=pex(peer_address),
                known_user_rooms=room_ids,
                room=room,
            )
            self._set_room_id_for_address(peer_address, room.room_id)

        is_peer_reachable = self._address_mgr.get_address_reachability(peer_address) is (
            AddressReachability.REACHABLE
        )
        if not is_peer_reachable:
            self.log.debug("Forcing presence update", peer_address=peer_address, user_id=sender_id)
            self._address_mgr.force_user_presence(user, UserPresence.ONLINE)
            self._address_mgr.refresh_address_presence(peer_address)

        messages = validate_and_parse_messages(event["content"]["body"], peer_address)

        if not messages:
            return False

        self.log.info(
            "Incoming messages",
            messages=messages,
            sender=pex(peer_address),
            sender_user=user,
            room=room,
        )

        for message in messages:
            if not isinstance(message, (SignedRetrieableMessage, SignedMessage)):
                self.log.warning("Received invalid message", message=message)
            if isinstance(message, Delivered):
                self._receive_delivered_to_lc(message)
            elif isinstance(message, Processed):
                self._receive_message_to_lc(message)
            else:
                assert isinstance(message, SignedRetrieableMessage)
                self._receive_message_to_lc(message)

        return True

    def _receive_delivered_to_lc(self, delivered: Delivered):
        self.log.debug(
            "Delivered message received", sender=pex(delivered.sender), message=delivered
        )

        assert self._raiden_service is not None
        self._raiden_service.on_message(delivered, True)

    def _receive_message_to_lc(self, message: Union[SignedRetrieableMessage, Processed]):
        print("<<---- Matrix Received Message LC transport" + str(message))
        assert self._raiden_service is not None
        self.log.debug(
            "Message received",
            node=pex(self._raiden_service.address),
            message=message,
            sender=pex(message.sender),
        )

        try:
            # Just manage the message, the Delivered response will be initiated by the LightClient invoking
            # send_for_light_client_with_retry
            self._raiden_service.on_message(message, True)

        except (InvalidAddress, UnknownAddress, UnknownTokenAddress):
            self.log.warning("Exception while processing message", exc_info=True)
            return
