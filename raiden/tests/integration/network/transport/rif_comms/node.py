import os
import signal
import subprocess
import time

import json5
import psutil

from raiden.tests.integration.network.transport.utils import generate_address
from transport.rif_comms.client import Client as RIFCommsClient

connections = {}  # hack to get around the fact that each connect() call needs to be assigned


class Config:
    comms_path = r"/home/rafa/repos/github/rsksmart/rif-communications-pubsub-node"
    api_endpoint_prefix = "localhost"
    env_file_prefix = "testing_"

    def __init__(self, node_number: int):
        # TODO: generate these files
        self.env_name = self.env_file_prefix + str(node_number)
        self.env_file = self.comms_path + '/config/' + self.env_name + '.json5'

        # read config file
        with open(self.env_file, 'r') as reader:
            config = json5.loads(reader.read())
            self.listening_port = config['grpcPort']

        self.address = generate_address()
        self.api_endpoint = self.api_endpoint_prefix + ":" + str(self.listening_port)


class Node:
    def __init__(self, config: Config):
        self.address = config.address
        self.api_endpoint = config.api_endpoint
        self.env_name = config.env_name

        self.client = RIFCommsClient(rsk_address=self.address, grpc_api_endpoint=self.api_endpoint)
        self.process = self.start()

    def start(self):
        # TODO: these should be dependencies within the project
        # TODO: look into using shell=False
        # FIXME: write output to memory or disk
        process = subprocess.Popen(
            "NODE_ENV=" + self.env_name + " npm run api-server",
            cwd=Config.comms_path,
            shell=True,
            preexec_fn=os.setsid,  # set to later kill process group
        )

        # FIXME: we need some sort of ping call, this will sometimes not be enough
        time.sleep(5)  # hack to get around calling the comms node before it is ready

        # FIXME: client.connect() calls should not need assignment (let alone to a module variable!)
        connections[self.address] = self.client.connect()

        return process

    def stop(self):
        try:
            # FIXME: deleting entries in the connections dictionary is causing non-crashing thread exceptions
            self.client.disconnect()
        finally:
            # TODO: we need a better way to stop the comms node process
            # terminate children and process group
            for child in psutil.Process(self.process.pid).children(recursive=True):
                child.kill()
            os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
