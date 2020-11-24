import os
import sys
from typing import List

import click
from eth_utils import to_canonical_address

from raiden.exceptions import RaidenError
from raiden.storage import sqlite, serialize
from raiden.utils import Address
from transport.layer import Layer as TransportLayer
from transport.node import Node as TransportNode
from transport.rif_comms.node import Node as RIFCommsTransportNode, LightClientNode


class Layer(TransportLayer[RIFCommsTransportNode]):

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
        pass

    def register_light_client(self, raiden_api: 'RaidenAPI', registration_data: dict) -> TransportNode:
        pass
