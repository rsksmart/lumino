#!/bin/bash

### Usage

## This script assumes:

# You have NVM installed
# You have NVM 14.13.1 installed
# You have ran npm install on the rif communications pub sub bootnode project
# You have created the config files for the rif communications pub sub bootnode (i.e /config/nodeA and keys/nodeA)
# You already know and configured the PORT in which rif comms node is going to run

## Running

# Run this script into the directory in which Lumino was git cloned
# Specify the node configuration and the port that its already configured: i.e ./startLuminoWithTransport.sh nodeA 5013
# The output log for rif comms node is on rif-communications-pub-sub-bootnode under the commsNodeLog.txt name

RIF_COMMS_NODE_CONFIGURATION=$1
RIF_COMMS_NODE_PORT=$2


# move to the previous folder where is the rif comms node
cd ..
cd rif-communications-pubsub-bootnode/

# load nvm
export NVM_DIR="$([ -z "${XDG_CONFIG_HOME-}" ] && printf %s "${HOME}/.nvm" || printf %s "${XDG_CONFIG_HOME}/nvm")"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh" # This loads nvm

# Set node version 14.13.1
nvm use v14.13.1

# Start rif comms node
export NODE_ENV=$RIF_COMMS_NODE_CONFIGURATION
npm run api-server > commsNodeLog.txt &

echo "Rif comms running, logs at "$(pwd)"/commsNodeLog.txt"

# Start lumino node

read -p "Press y to start lumino " -n 1 -r
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    COMMS_PID=$(lsof -sTCP:LISTEN -ti :$RIF_COMMS_NODE_PORT)
    echo "Killing rif comms process: "$COMMS_PID
    kill -9 $COMMS_PID
else
    cd ..
    cd lumino
    ./startLumino.sh
fi
