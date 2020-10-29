import os
import sys
from typing import Dict, Any, List
from urllib.parse import urlparse

import click
from eth_utils import to_normalized_address, decode_hex, remove_0x_prefix

from raiden.api.python import RaidenAPI
from raiden.constants import PATH_FINDING_BROADCASTING_ROOM, MONITORING_BROADCASTING_ROOM
from raiden.exceptions import RaidenError
from raiden.network.transport import MatrixNode as MatrixTransportNode
from raiden.network.transport.matrix import MatrixLightClientNode as MatrixLightClientTransportNode
from raiden.network.transport.matrix.utils import get_available_servers_from_config, server_is_available, make_client
from raiden.settings import DEFAULT_MATRIX_KNOWN_SERVERS
from raiden.storage import sqlite, serialize
from raiden.transfer import views
from raiden.utils import typing
from raiden.utils.cli import get_matrix_servers
from raiden.utils.signer import recover
from transport.layer import Layer as TransportLayer
from transport.node import Node as TransportNode


class MatrixLayer(TransportLayer):

    def __init__(self, config: Dict[str, Any]):
        from raiden.ui.app import log

        self.environment_type = config["environment_type"]

        if config["transport"]["matrix"].get("available_servers") is None:
            # fetch list of known servers from raiden-network/raiden-tranport repo
            available_servers_url = DEFAULT_MATRIX_KNOWN_SERVERS[self.environment_type]
            available_servers = get_matrix_servers(available_servers_url)
            log.debug("Fetching available matrix servers", available_servers=available_servers)
            config["transport"]["matrix"]["available_servers"] = available_servers

        # TODO: This needs to be adjusted once #3735 gets implemented
        # Add PFS broadcast room if enabled
        if config["services"]["pathfinding_service_address"] is not None:
            if PATH_FINDING_BROADCASTING_ROOM not in config["transport"]["matrix"]["global_rooms"]:
                config["transport"]["matrix"]["global_rooms"].append(PATH_FINDING_BROADCASTING_ROOM)

        # Add monitoring service broadcast room if enabled
        if config["services"]["monitoring_enabled"] is True:
            config["transport"]["matrix"]["global_rooms"].append(MONITORING_BROADCASTING_ROOM)

        try:

            database_path = config["database_path"]

            database_dir = os.path.dirname(config["database_path"])
            os.makedirs(database_dir, exist_ok=True)

            storage = sqlite.SerializedSQLiteStorage(
                database_path=database_path, serializer=serialize.JSONSerializer()
            )

            light_clients = storage.get_all_light_clients()

            self._light_clients: List[TransportNode] = []

            for light_client in light_clients:
                current_server_name = None

                if light_client["current_server_name"]:
                    current_server_name = light_client["current_server_name"]
                    available_servers = get_available_servers_from_config(config["transport"]["matrix"])
                    if not server_is_available(current_server_name, available_servers):
                        # we flag the light client as pending for deletion because it's associated to a server that
                        # is not available anymore so we need to force a new on-boarding, the next request from that LC will
                        # delete it and respond with an error to control the re-onboard
                        storage.flag_light_client_as_pending_for_deletion(light_client["address"])
                        log.info("No available server with name " + current_server_name +
                                 ", LC has been flagged for deletion from DB, on-boarding is needed for LC with address: " +
                                 light_client["address"])
                        continue

                matrix_config = config["transport"]["matrix"]
                matrix_config["current_server_name"] = current_server_name
                auth_params = {
                    "light_client_password": light_client["password"],
                    "light_client_display_name": light_client["display_name"],
                    "light_client_seed_retry": light_client["seed_retry"]
                }
                light_client_transport = MatrixLightClientTransportNode(
                    light_client['address'],
                    matrix_config,
                    auth_params,
                )

                self._light_clients.append(light_client_transport)

            self._full_node: TransportNode = MatrixTransportNode(config["address"], config["transport"]["matrix"])

        except RaidenError as ex:
            click.secho(f"FATAL: {ex}", fg="red")
            sys.exit(1)

    @property
    def full_node(self) -> TransportNode:
        return self._full_node

    @property
    def light_clients(self) -> List[TransportNode]:
        return self._light_clients

    def light_client_onboarding_data(self, address: typing.Address) -> dict:
        # fetch list of known servers from raiden-network/raiden-tranport repo
        available_servers_url = DEFAULT_MATRIX_KNOWN_SERVERS[self.environment_type]
        available_servers = get_matrix_servers(available_servers_url)

        client = make_client(available_servers)
        server_url = client.api.base_url
        server_name = urlparse(server_url).netloc
        return {
            "display_name_to_sign": "@" + to_normalized_address(address) + ":" + server_name,
            "password_to_sign": server_name,
            "seed_retry": "seed",
        }

    def register_light_client(self, raiden_api: RaidenAPI, registration_data: dict) -> TransportNode:
        config = raiden_api.raiden.config["transport"]["matrix"]

        password = registration_data["password"]
        signed_password = registration_data["signed_password"]
        signed_display_name = registration_data["signed_display_name"]

        # Recover light client address from password and signed_password
        address_recovered_from_signed_password = recover(
            data=password.encode(),
            signature=decode_hex(signed_password)
        )

        display_name = registration_data["display_name"]
        # Recover light client address from display and signed_display_name
        address_recovered_from_signed_display_name = recover(
            data=display_name.encode(),
            signature=decode_hex(signed_display_name)
        )

        seed_retry, signed_seed_retry = registration_data["seed_retry"], registration_data["signed_seed_retry"]
        # Recover light client address from seed retry and signed_seed_retry
        address_recovered_from_signed_seed_retry = recover(
            data=seed_retry.encode(),
            signature=decode_hex(signed_seed_retry)
        )

        address = bytearray.fromhex(remove_0x_prefix(registration_data['address']))
        if address_recovered_from_signed_password != address or \
            address_recovered_from_signed_display_name != address or \
            address_recovered_from_signed_seed_retry != address:
            return None  # an error has occurred, so no light client is returned

        light_client = raiden_api.save_light_client(
            address,
            signed_password,
            password,
            signed_display_name,
            signed_seed_retry
        )

        if light_client and light_client["result_code"] == 200:
            auth_params = {
                "light_client_password": light_client["encrypt_signed_password"],
                "light_client_display_name": light_client["encrypt_signed_display_name"],
                "light_client_seed_retry": light_client["encrypt_signed_seed_retry"]
            }
            light_client_transport = MatrixLightClientTransportNode(
                address=light_client["address"],
                config=config,
                auth_params=auth_params,
            )

            raiden_api.raiden.start_transport_in_runtime(
                transport=light_client_transport,
                chain_state=views.state_from_raiden(raiden_api.raiden)
            )

            self.add_light_client(light_client_transport)

        return light_client

    def add_light_client(self, light_client_transport: TransportNode):
        self._light_clients.append(light_client_transport)

    def remove_light_client(self, light_client_transport: TransportNode):
        self._light_clients.remove(light_client_transport)
