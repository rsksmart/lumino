import os
import signal
import subprocess
import time
from pathlib import Path
from subprocess import Popen

import psutil

# FIXME: this should be a dependency within the project
# path to the RIF Comms Node repo
RIF_COMMS_PATH = Path(__file__).parents[7].joinpath('rif-communications-pubsub-bootnode')


class Process:
    """
    Utility class for starting and stopping RIF Comms node processes through npm.
    """

    @staticmethod
    def start(env_name: str) -> Popen:
        """
        Start a RIF Comms node process through npm, with the given environment name.
        The RIF Comms Pub-Sub Bootnode repo must be at RIF_COMMS_PATH.
        """
        # TODO: look into using shell=False
        # FIXME: write output to memory or disk
        process = subprocess.Popen(
            "NODE_ENV=" + env_name + " npm run api-server",
            cwd=RIF_COMMS_PATH,
            shell=True,
            preexec_fn=os.setsid,  # set to later kill process group
        )

        # FIXME: we need some sort of ping call, this might sometimes not be enough
        time.sleep(7)  # hack to get around calling the comms node before it is ready

        return process

    @staticmethod
    def stop(process: Popen):
        """
        Kill a RIF Comms node process with the given process ID (PID),
        """
        # FIXME: find a better way to stop the comms node process
        # terminate children and process group
        pid = process.pid
        for child in psutil.Process(pid).children(recursive=True):
            child.kill()
        os.killpg(os.getpgid(pid), signal.SIGTERM)
