from subprocess import Popen

import json5

from raiden.tests.integration.network.transport.rif_comms.process import RIF_COMMS_PATH, Process as CommsProcess
from raiden.tests.integration.network.transport.utils import generate_address
from transport.rif_comms.client import Client as RIFCommsClient


class Config:
    """
    Class to load and set configuration attributes for a RIF Comms node to be run.
    """

    api_endpoint_prefix = "localhost"
    env_file_prefix = "testing_"

    def __init__(self, node_number: int):
        """
        Load and set a configuration attributes for a RIF Comms node.
        A valid configuration file must exist at RIF_COMMS_PATH/config/testing_<node_number>.json5
        """
        self.env_name = self.env_file_prefix + str(node_number)
        # TODO: generate these files if needed
        self._env_file = RIF_COMMS_PATH.joinpath('config/' + self.env_name + '.json5')

        # load config from file
        with open(self._env_file, 'r') as reader:
            config = json5.loads(reader.read())
            self._listening_port = config['grpcPort']

        self.address = generate_address()
        self.api_endpoint = self.api_endpoint_prefix + ":" + str(self._listening_port)


class Node:
    """
    Class for RIF Comms node program.
    """

    def __init__(self, config: Config):
        self.address = config.address
        self._api_endpoint = config.api_endpoint
        self._env_name = config.env_name

        self.client = RIFCommsClient(rsk_address=self.address, grpc_api_endpoint=self._api_endpoint)
        self._process = self.start()

    def start(self) -> Popen:
        """
        Start a RIF Comms node process and connect to it.
        """
        process = CommsProcess.start(env_name=self._env_name)
        # FIXME: failing sometimes
        self.client.connect()
        return process

    def stop(self):
        """
        Disconnect from RIF Comms node program, and stop its process.
        """
        try:
            self.client.disconnect()
        finally:
            CommsProcess.stop(process=self._process)
