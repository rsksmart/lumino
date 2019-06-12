import requests
import structlog

log = structlog.get_logger(__name__)


def register(explorer_endpoint, rsk_address, rns_domain):
    try:
        r = requests.post(explorer_endpoint + 'luminoNode/',
                          json={'node_address': rsk_address, 'rns_address': rns_domain})
        if r.status_code == 200:
            log.info("Succesfully registered into Lumino Explorer")
        else:
            log.info("Warning: There was an error registering into Lumino Explorer. Status: " + str(r.status_code))
    except requests.exceptions.RequestException as e:
        log.info("Warning: Could not connect to Lumino Explorer. Your node will not be registered.")





