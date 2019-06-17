import requests
from datetime import datetime
import json
import structlog
from raiden.transfer import views

log = structlog.get_logger(__name__)


def notice_explorer_to_be_alive(endpoint_explorer, discoverable, node_address, raiden_instance):
    """
        Notice api explorer what node is alive, sending a
        HTTP request
    """
    try:

        raiden = raiden_instance
        channels = views.list_all_channelstate(chain_state=views.state_from_raiden(raiden))

        if discoverable and len(channels) == 0 and endpoint_explorer:

            url = endpoint_explorer + "luminoNode/" + node_address

            response = requests.get(url)

            if response.status_code == 200:
                json_data = json.loads(response.text)
                data = json_data['data']
                data['last_alive_signal'] = datetime.utcnow().isoformat()

                headers = {'Content-type': 'application/json', 'Accept': 'application/json'}

                response = requests.put(url, json=data, headers=headers)

                if response.status_code == 200:
                    log.info("Succesfully send alive signal to Lumino Explorer")
                else:
                    log.info("Warning: There was an error sending alive signal to Lumino Explorer. Status: " +
                             str(response.status_code))
            else:
                log.info("Warning: send alive signal to Lumino Explorer, is not posible because node is not registered")

    except requests.exceptions.RequestException as e:
        log.info("Warning: Could not connect to Lumino Explorer. Your node will not send alive signal.")

