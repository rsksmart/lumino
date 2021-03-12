## Docker Environment file

The docker environment file `lumino/docker/.env` contains the environment
variables that are needed to setup the lumino docker environment correctly.

The file looks something like this:

```dotenv
TOKEN_NETWORK_REGISTRY=0xed8c9163F888Bc2f9C4F299325003DA5fC8676DD
SECRET_REGISTRY=0xDbc02f59135811A934A7131A4013411696cE03f4
ENDPOINT_REGISTRY=0xac7c09C3FFA333ca1bB6C9D7F7A2E7c55f11d2A9
HUB_MODE=disabled
RSK_ENDPOINT=http://localhost:4444
NODE_PORT=5001
NETWORK_ID=33
GRPC_PORT=6012
```

Where the values are explained here:

* **TOKEN_NETWORK_REGISTRY:** **(required)** is the token network registry contract address on your network.
* **SECRET_REGISTRY:** **(required)** is the token secret registry contract address on your network.
* **ENDPOINT_REGISTRY:** **(required)** is the token endpoint registry contract address on your network.
* **HUB_MODE:** **(optional)** indicates if the lumino node run's on hub mode or not, valid values are `enabled` and `disabled`. 
  By default is `disabled`.
* **RSK_ENDPOINT:** **(optional)** set the rsk node endpoint location, by default is `http://localhost:4444`.
* **NODE_PORT:** **(optional)** the port where the lumino node will be exposed, by default is `5001`
* **NETWORK_ID:** **(optional)** indicates the chain id to be used by the lumino node, by default is `33`.
* **GRPC_PORT:** **(optional)** is the GRPC port where the rif-comms node will be running, by default is `6012`.