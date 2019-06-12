import requests
from datetime import datetime
import json
import structlog

log = structlog.get_logger(__name__)


def notice_explorer_to_be_alive(endpoint_explorer, node_address):
    """
        Notice api explorer what node is alive, sending a
        HTTP request
    """
    try:

        payload = {
            'last_alive_signal': datetime.utcnow().isoformat()
        }

        headers = {'Content-type': 'application/json', 'Accept': 'application/json'}

        url = endpoint_explorer + "luminoNode/" + node_address

        response = requests.put(url, data=json.dumps(payload), headers=headers)

        if response.status_code == 200:
            log.info("Succesfully send alive signal to Lumino Explorer")
        else:
            log.info("Warning: There was an error registering into Lumino Explorer. Status: " + str(response.status_code))

    except requests.exceptions.RequestException as e:
        log.info("Warning: Could not connect to Lumino Explorer. Your node will not send alive signal.")

