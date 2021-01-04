import os
import sys
from typing import List

import click
from eth_utils import to_canonical_address, remove_0x_prefix
from raiden.exceptions import RaidenError
from raiden.lightclient.handlers.light_client_service import LightClientService
from raiden.storage import sqlite, serialize
from raiden.transfer import views
from raiden.utils import Address
from transport.layer import Layer as TransportLayer
from transport.node import Node as TransportNode
from transport.rif_comms.node import Node as RIFCommsTransportNode, LightClientNode


class Layer(TransportLayer[RIFCommsTransportNode]):
    transport_type = "rif-comms"

    def construct_full_node(self, config):
        return RIFCommsTransportNode(config["address"], config["transport"]["rif_comms"])

    def construct_light_clients_nodes(self, config):
        try:

            database_path = config["database_path"]

            database_dir = os.path.dirname(config["database_path"])
            os.makedirs(database_dir, exist_ok=True)

            storage = sqlite.SerializedSQLiteStorage(
                database_path=database_path, serializer=serialize.JSONSerializer()
            )

            light_clients = storage.get_all_light_clients()

            result: List[TransportNode] = []

            for light_client in light_clients:
                light_client_transport = LightClientNode(to_canonical_address(light_client['address']),
                                                         config["transport"]["rif_comms"])
                result.append(light_client_transport)
            return result
        except RaidenError as ex:
            click.secho(f"FATAL: {ex}", fg="red")
            sys.exit(1)

    def light_client_onboarding_data(self, address: Address) -> dict:
        return {
            "transport_type": self.transport_type,
        }

    def register_light_client(self, raiden_api: 'RaidenAPI', registration_data: dict):
        config = raiden_api.raiden.config["transport"]["rif_comms"]
        lc_address = bytearray.fromhex(remove_0x_prefix(registration_data['address']))

        light_client = LightClientService.store_rif_comms_light_client(
            lc_address, raiden_api.raiden.wal.storage
        )

        if light_client and light_client["result_code"] == 200:
            light_client_transport = LightClientNode(
                address=lc_address,
                config=config
            )
            raiden_api.raiden.start_transport_in_runtime(
                transport=light_client_transport,
                chain_state=views.state_from_raiden(raiden_api.raiden)
            )
            self.add_light_client(light_client_transport)

        return light_client

    def get_light_client_transport_node(self, address) -> LightClientNode:
        # RIFCommsTransportNode addresses are bytes, therefore we ensure the comparison is correct
        # by using the `to_canonical_address` method on the received address parameter.
        rif_comms_address = to_canonical_address(address)
        for light_client_transport in self.light_clients:
            if rif_comms_address == light_client_transport.address:
                return light_client_transport
        return None
