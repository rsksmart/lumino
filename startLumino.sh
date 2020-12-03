#!/bin/bash

# How it works
# ./startLumino <ENVIRONMENT_NAME>
# This script is to start lumino using an environment called <ENVIRONMENT_NAME>.
# ENVIRONMENT_NAME defaults to luminoNode

# Here some explanation of the parameters:
# ADDRESS_TO_USE: The address to set to be used by the node
# PASSWORD_FILE_CONTENT: The password for the private key of the ADDRESS_TO_USE address.
# TOKEN_NETWORK_REGISTRY: The token network registry contract address to be used by the node.
# SECRET_REGISTRY: The secret registry contract address to be used by the node.
# ENDPOINT_REGISTRY: The endpoint registry contract address to be used by the node.
# HUB_MODE: Sets if the node will be a hub or not
# RSK_ENDPOINT: The RSK endpoint url
# EXPOSE_ENDPOINT: The expose url to use by the lumino node
# PORT: The port number to setup for the lumino node
# NETWORK_ID: The network id to connect to

ENV_NAME=$1

if [ "" == "${ENV_NAME}" ]; then
  ENV_NAME=clientEnv
fi

KETYSTORE_PATH="/home/marcos/rsk/keystore"
TOKEN_NETWORK_REGISTRY="0x07e1CD1ea2123e3a0f624553761EaD1c1e150CC3"
SECRET_REGISTRY="0xfA8Bc06C815BD4C4bB641ccb00EBF9CB8BEB2d67"
ENDPOINT_REGISTRY="0xC14E9A67A87949bC131b9f22a4EB5cd9d9A6728e"
HUB_MODE=0
RSK_ENDPOINT=http://localhost:4444
EXPOSE_ENDPOINT=http://localhost
PORT=5001
NETWORK_ID=33

trap ctrl_c INT

function ctrl_c() {
    rm password-file.txt
	source deactivate
}

function args() {
    options=$(getopt -o hp --long hub --long port: -- "$@")
    [ $? -eq 0 ] || {
        echo "Incorrect option provided"
        exit 1
    }
    eval set -- "$options"
    while true; do
        case "$1" in
        --hub|-h)
            HUB_MODE=1
            echo "Hub Mode Activated!"
            ;;
        --port|-p)
            shift; # The arg is next in position args
            PORT=$1
            if [[ "" == "${port}" ]]; then
                echo "Invalid Port Number!"
                exit 1
            fi
            ;;
        --)
            shift
            break
            ;;
        esac
        shift
    done
}

args $0 "$@"

source ${ENV_NAME}/bin/activate

echo ${PASSWORD_FILE_CONTENT} > password-file.txt

if [[ ${HUB_MODE} == 1 ]]; then
    lumino  --accept-disclaimer --hub-mode --keystore-path $KETYSTORE_PATH --network-id ${NETWORK_ID} --eth-rpc-endpoint ${RSK_ENDPOINT} --environment-type development --tokennetwork-registry-contract-address=${TOKEN_NETWORK_REGISTRY} --secret-registry-contract-address=${SECRET_REGISTRY} --endpoint-registry-contract-address=${ENDPOINT_REGISTRY} --no-sync-check --api-address=${EXPOSE_ENDPOINT}:${PORT}
else
    lumino  --accept-disclaimer --keystore-path $KETYSTORE_PATH --network-id ${NETWORK_ID} --eth-rpc-endpoint ${RSK_ENDPOINT} --environment-type development --tokennetwork-registry-contract-address=${TOKEN_NETWORK_REGISTRY} --secret-registry-contract-address=${SECRET_REGISTRY} --endpoint-registry-contract-address=${ENDPOINT_REGISTRY} --no-sync-check --api-address=${EXPOSE_ENDPOINT}:${PORT}
fi