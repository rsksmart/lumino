import requests
import structlog
from datetime import datetime

log = structlog.get_logger(__name__)


def register(explorer_endpoint, rsk_address, rns_domain):
    try:

        if rns_domain is None:
            rns_domain = ''

        data_registry = {'node_address': rsk_address,
                         'rns_address': rns_domain,
                         'last_alive_signal': datetime.utcnow().isoformat()}

        response = requests.post(explorer_endpoint + 'luminoNode/', json=data_registry)
        if response.status_code == 200:
            log.info("Succesfully registered into Lumino Explorer")
        else:
            log.info("Warning: There was an error registering into Lumino Explorer. Status: " + str(response.status_code))
    except requests.exceptions.RequestException as e:
        log.info("Warning: Could not connect to Lumino Explorer. Your node will not be registered.")





