import requests

explorer_endpoint = "https://api.lumino.rifos.org/lumino-explorer-1.0/"


def register(rsk_address, rns_domain):
    try:
        r = requests.post(explorer_endpoint + 'luminoNode/',
                          json={'node_address': rsk_address, 'rns_address': rns_domain})
        if r.status_code == 200:
            print("Succesfully registered into Lumino Explorer")
        else:
            print("Warning: There was an error registering into Lumino Explorer. Status: " + str(r.status_code))
    except requests.exceptions.RequestException as e:
        print("Warning: Could not connect to Lumino Explorer. Your node will not be registered.")





