#!/bin/bash

### Usage

## This script assumes:

# You have node 14.13.1 installed
# You have ran npm install on the rif communications pub sub bootnode project
# You have created the config files for the rif communications pub sub bootnode (i.e /config/nodeA and keys/nodeA)
# You already know and configured the PORT in which rif comms node is going to run

## Running

# Run this script in the directory in which Lumino was git cloned
# Specify the flags that are part of ARGUMENT_LIST, i.e
#
#. /startLuminoWithRIFComms.sh --RIF_COMMS_NODE_DIR="~/rsk/rif-communications-pubsub-bootnode" --KEYSTORE_PATH="/home/marcos/rsk/keystore" --TOKEN_NETWORK_REGISTRY="0x07e1CD1ea2123e3a0f624553761EaD1c1e150CC3" --SECRET_REGISTRY="0xfA8Bc06C815BD4C4bB641ccb00EBF9CB8BEB2d67" --ENDPOINT_REGISTRY="0xC14E9A67A87949bC131b9f22a4EB5cd9d9A6728e" --HUB_MODE=0 --RSK_ENDPOINT="http://localhost:4444" --LUMINO_API_ENDPOINT="http://localhost:5001" --NETWORK_ID=33 --RIF_COMMS_NODE_CONFIGURATION="nodeA"

## Here some explanation of the parameters:

## TOKEN_NETWORK_REGISTRY: The token network registry contract address to be used by the node.
## SECRET_REGISTRY: The secret registry contract address to be used by the node.
## ENDPOINT_REGISTRY: The endpoint registry contract address to be used by the node.
## HUB_MODE: If set, the node will work as a hub
## RSK_ENDPOINT: The RSK node endpoint URL
## LUMINO_API_ENDPOINT: The expose url to use by the lumino node
## NETWORK_ID: the blockchain network ID to connect to
## RIF_COMMS_NODE_CONFIGURATION: config file of the rif comms node


# The output log for rif comms node is on rif-communications-pubsub-bootnode under the commsNodeLog.txt name

ARGUMENT_LIST=(
    "RIF_COMMS_NODE_DIR"
    "KEYSTORE_PATH"
    "TOKEN_NETWORK_REGISTRY"
    "SECRET_REGISTRY"
    "ENDPOINT_REGISTRY"
    "HUB_MODE"
    "RSK_ENDPOINT"
    "LUMINO_API_ENDPOINT"
    "NETWORK_ID"
    "RIF_COMMS_NODE_CONFIGURATION"
    "RIF_COMMS_ENDPOINT"
)


# read arguments
opts=$(getopt \
    --longoptions "$(printf "%s:," "${ARGUMENT_LIST[@]}")" \
    --name "$(basename "$0")" \
    --options "" \
    -- "$@"
)

eval set --$opts

while [[ $# -gt 0 ]]; do
    case "$1" in
        --RIF_COMMS_NODE_DIR)
            RIF_COMMS_NODE_DIR=$2
            shift 2
            ;;
        --KEYSTORE_PATH)
            KEYSTORE_PATH=$2
            shift 2
            ;;
        --TOKEN_NETWORK_REGISTRY)
            TOKEN_NETWORK_REGISTRY=$2
            shift 2
            ;;
        --SECRET_REGISTRY)
            SECRET_REGISTRY=$2
            shift 2
            ;;
        --ENDPOINT_REGISTRY)
            ENDPOINT_REGISTRY=$2
            shift 2
            ;;
        --HUB_MODE)
            HUB_MODE=$2
            shift 2
            ;;
        --RSK_ENDPOINT)
            RSK_ENDPOINT=$2
            shift 2
            ;;
        --LUMINO_API_ENDPOINT)
            LUMINO_API_ENDPOINT=$2
            shift 2
            ;;
        --NETWORK_ID)
            NETWORK_ID=$2
            shift 2
            ;;
        --RIF_COMMS_NODE_CONFIGURATION)
            RIF_COMMS_NODE_CONFIGURATION=$2
            shift 2
            ;;
         --RIF_COMMS_ENDPOINT)
            RIF_COMMS_ENDPOINT=$2
            shift 2
            ;;
        *)
            break
            ;;
    esac
done

# Start rif comms node
export NODE_ENV=$RIF_COMMS_NODE_CONFIGURATION
npm run api-server --prefix="${RIF_COMMS_NODE_DIR}" > commsNodeLog.log 2>&1 &

echo "Rif comms running, logs at "$(pwd)"/commsNodeLog.log"

# Wait a certain time to rif comms node start up
sleep 5

# Start lumino node
read -p "Press y to start lumino " -n 1 -r
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    echo "Shutting down rif comms node"
    pkill -f api-server & pkill -f tasegir
else
    echo "Lumino is starting..."
    ./startLumino.sh --KEYSTORE_PATH=$KEYSTORE_PATH --TOKEN_NETWORK_REGISTRY=$TOKEN_NETWORK_REGISTRY --SECRET_REGISTRY=$SECRET_REGISTRY --ENDPOINT_REGISTRY=$ENDPOINT_REGISTRY --HUB_MODE=$HUB_MODE --RSK_ENDPOINT=$RSK_ENDPOINT --LUMINO_API_ENDPOINT=$LUMINO_API_ENDPOINT --NETWORK_ID=$NETWORK_ID --RIF_COMMS_ENDPOINT=$RIF_COMMS_ENDPOINT
fi
