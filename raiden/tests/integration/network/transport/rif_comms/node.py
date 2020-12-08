import os
import signal
import subprocess
import time

import psutil

from raiden.tests.integration.network.transport.utils import generate_address
from transport.rif_comms.client import Client as RIFCommsClient

connections = {}  # hack to get around the fact that each connect() call needs to be assigned


class Node:
    def __init__(self, config: 'Config'):
        self.address = config.address
        self.api_endpoint = config.api_endpoint
        self.env_file = config.env_file

        self.client = RIFCommsClient(rsk_address=self.address, grpc_api_endpoint=self.api_endpoint)
        self.process = self.start()

    def start(self):
        # TODO: these should be dependencies within the project
        # TODO: look into using shell=False
        # FIXME: write output to memory or disk
        process = subprocess.Popen(
            "NODE_ENV=" + self.env_file + " npm run api-server",
            cwd=r"/home/rafa/repos/github/rsksmart/rif-communications-pubsub-node",
            shell=True,
            preexec_fn=os.setsid,  # set to later kill process group
        )

        # FIXME: we need some sort of ping call
        time.sleep(5)  # hack to get around calling the comms node before it is ready

        # FIXME: client.connect() calls should not need assignment (let alone to a module variable!)
        connections[self.address] = self.client.connect()

        return process

    def stop(self):
        try:
            self.client.disconnect()
            del connections[self.address]
        finally:
            # terminate children and process group
            for child in psutil.Process(self.process.pid).children(recursive=True):
                child.kill()
            os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)


class Config:
    starting_port = 5013
    api_endpoint_prefix = "localhost"
    env_file_prefix = "development"

    def __init__(self, node_number: int):
        self.address = generate_address()
        self.api_endpoint = self.api_endpoint_prefix + ":" + str(
            self.starting_port + (node_number - 1) * 1000  # 5013, 6013, 7013...
        )
        # TODO: generate these files
        self.env_file = self.env_file_prefix + str(1 + node_number)  # development2, development3...
