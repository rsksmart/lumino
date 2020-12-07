#!/bin/bash

# How it works

# This script is to start lumino using an environment called clientEnv

# Preconditions:
# 1. You must have a venv activated, called clientEnv

# Usage:
# You must specify the arguments that are part of ARGUMENT_LIST, i.e:
## ./startLumino.sh --KEYSTORE_PATH="/home/marcos/rsk/keystore" --TOKEN_NETWORK_REGISTRY="0x07e1CD1ea2123e3a0f624553761EaD1c1e150CC3" --SECRET_REGISTRY="0xfA8Bc06C815BD4C4bB641ccb00EBF9CB8BEB2d67" --ENDPOINT_REGISTRY="0xC14E9A67A87949bC131b9f22a4EB5cd9d9A6728e" --HUB_MODE=0 --RSK_ENDPOINT="http://localhost:4444" --LUMINO_API_ENDPOINT="http://localhost:5001" --NETWORK_ID=33

## Here some explanation of the parameters:
## TOKEN_NETWORK_REGISTRY: The token network registry contract address to be used by the node.
## SECRET_REGISTRY: The secret registry contract address to be used by the node.
## ENDPOINT_REGISTRY: The endpoint registry contract address to be used by the node.
## HUB_MODE: If set, the node will work as a hub
## RSK_ENDPOINT: The RSK node endpoint URL
## LUMINO_API_ENDPOINT: The expose url to use by the lumino node
## NETWORK_ID: the blockchain network ID to connect to

ARGUMENT_LIST=(
    "KEYSTORE_PATH"
    "TOKEN_NETWORK_REGISTRY"
    "SECRET_REGISTRY"
    "ENDPOINT_REGISTRY"
    "HUB_MODE"
    "RSK_ENDPOINT"
    "LUMINO_API_ENDPOINT"
    "NETWORK_ID"
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
        *)
            break
            ;;
    esac
done


if [[ ${HUB_MODE} == 1 ]]; then
    lumino  --accept-disclaimer --hub-mode --keystore-path $KEYSTORE_PATH --network-id ${NETWORK_ID} --eth-rpc-endpoint ${RSK_ENDPOINT} --environment-type development --tokennetwork-registry-contract-address=${TOKEN_NETWORK_REGISTRY} --secret-registry-contract-address=${SECRET_REGISTRY} --endpoint-registry-contract-address=${ENDPOINT_REGISTRY} --no-sync-check --api-address=${LUMINO_API_ENDPOINT}
else
    lumino  --accept-disclaimer --keystore-path $KEYSTORE_PATH --network-id ${NETWORK_ID} --eth-rpc-endpoint ${RSK_ENDPOINT} --environment-type development --tokennetwork-registry-contract-address=${TOKEN_NETWORK_REGISTRY} --secret-registry-contract-address=${SECRET_REGISTRY} --endpoint-registry-contract-address=${ENDPOINT_REGISTRY} --no-sync-check --api-address=${LUMINO_API_ENDPOINT}
fi