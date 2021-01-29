# Get your own RIF Lumino node up and running on MacOS

## Prerequisites

1. Access to a synched RSK node. You can do this in a variety of ways:
	1. Run your own node on TestNet or MainNet, see [https://github.com/rsksmart/rskj/wiki/Install-RskJ-and-join-the-RSK-Orchid-Mainnet-Beta](https://github.com/rsksmart/rskj/wiki/Install-RskJ-and-join-the-RSK-Orchid-Mainnet-Beta)
	2. Compile and run a RSK node locally, see [https://github.com/rsksmart/rskj/wiki/Compile-and-run-a-RSK-node-locally](https://github.com/rsksmart/rskj/wiki/Compile-and-run-a-RSK-node-locally)
2. An RSK account with an RBTC balance NOT lower than 0.001 RBTC
3. XCode

## Install required libraries/software

### Install command line tools

```
xcode-select --install
```

### Install Homebrew

From a Terminal window run:

```
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```

### Install OpenSSL

```
brew install openssl
export LC_ALL="en_US.UTF-8"\nexport LC_CTYPE="en_US.UTF-8"
export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/opt/openssl/lib/
```

### Install Python 3.7


```
brew install python3
```

### Install PIP

```
sudo easy_install pip
```

### Install virtualenv



```
pip3 install virtualenv
```

### Install libpq

```
brew install libpq
```

### Install postgresql

```
brew install postgresql
```

### Install psycopg2

```
env LDFLAGS="-I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib" pip install psycopg2
```


## Build RIF Lumino from code

1. Get the code from [https://github.com/rsksmart/lumino/releases/tag/1.0.0](https://github.com/rsksmart/lumino/releases/tag/1.0.0)
2. Uncompress the downloaded file
2. Go to the path you uncompressed the code in the previous step (lets call this path `$RIF_LUMINO_PATH`)
3. Create python virtual env for RIF Lumino (this needs to be performed only once) and execute the following command:

```
virtualenv -p <PATH_TO_PYTHON3.7> clientEnv
```

**Note:**
Replace `<PATH_TO_PYTHON3.7>` with the path where Python3.7 is installed in your system. In the case of MacOS, this is usually `/usr/local/bin/python3.7`

4. Activate python virtual env, by executing the following command:

```
source clientEnv/bin/activate
```

5. Check if the Python version is correct inside the virtual environment by running:

```
python --version
```

This command should output version 3.7.x

6. Install RIF Lumino requirements. Inside the virtual environment run the following command (this could take a few minutes):

```
pip install -c constraints.txt --upgrade -r requirements-dev.txt
```

7. Run Lumino setup with the following command:

```
python setup.py develop
```

## Start RIF Communications transport layer
	
	The communication between Lumino nodes can be done both using RIF Communications (https://www.rifos.org/communications) and Matrix (https://matrix.org/).
	
	The default way, and the one encouraged to be used for a more decentralized ecosystem, is RIF Communications. 
	
	In order to run Lumino using RIF Comms, you need to set up the RIF Communications node. To use Matrix, no configuration is required. 
	
### Set up a RIF Communications bootnode

Please follow the instructions in the (RIF Communications installation page)[https://github.com/rsksmart/rif-communications-pubsub-bootnode/tree/grpc-api].


## Start your RIF Lumino Node

1. Go to `$RIF_LUMINO_PATH`.
2. If you haven't executed it before, run `source clientEnv/bin/activate` to activate the virtual environment.
3. Run the following command to start Lumino:
    
    ```shell script
    lumino
        --keystore-path $KEYSTORE_PATH
        --network-id 33
        --eth-rpc-endpoint $RSK_NODE_URL
        --environment-type development
        --tokennetwork-registry-contract-address $TOKENNETWORK_REGISTRY_CONTRACT_ADDRESS
        --secret-registry-contract-address $SECRET_REGISTRY_CONTRACT_ADDRESS
        --endpoint-registry-contract-address $ENDPOINT_REGISTRY_CONTRACT_ADDRESS
        --no-sync-check
        --api-address 127.0.0.1:5001
        --rnsdomain $YOUR_RNS_DOMAIN
        --discoverable # if this flag is present, then your node will be registered on Lumino Explorer
        --hub-mode # if this flag is present, then your node will run in HUB mode
        --transport 
        --grpc-endpoint # grpc endpoint of RIF Communications node  

    ```
    
    | FIELD                                     | DESCRIPTION                                                                                                                             |
    |-------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
    | `$KEYSTORE_PATH`                          | The path to your keystore folder.                                                                                                       |
    | `network-id`                              | The blockchain network ID you're connecting to. This must match the RSK node you're connecting to. `33` is regtest.                     |
    | `$RSK_NODE_URL`                           | URL of the RSK node to connect to (`http://URL:PORT`). If you're running a local node, this will typically be `http://localhost:4444/`. |
    | `environment-type`                        | You will need this set to `development` in order to use custom blockchain and contract addresses.                                       |
    | `$TOKENNETWORK_REGISTRY_CONTRACT_ADDRESS` | Address for the token registry contract deployed (view contracts table).                                                                |
    | `$SECRET_REGISTRY_CONTRACT_ADDRESS`       | Address for the secret registry contract deployed (view contracts table).                                                               |
    | `$ENDPOINT_REGISTRY_CONTRACT_ADDRESS`     | Address for the endpoint registry contract deployed (view contracts table).                                                             |
    | `no-sync-check`                           | This will allow you to bypass checking that the node is synchronized against etherscan.                                                 |
    | `$YOUR_RNS_DOMAIN`                        | You can supply the RNS address associated with your RSK node address, e.g. `--rnsdomain=lumino.rsk.co`                                 |
    | `transport`                               | Transport mode for Lumino, rif-comms and matrix are supported. Defaults to rif-comms, e.g. `--transport=matrix`                                 |
    | `grpc-endpoint` | The communication endpoint for the RIF Comms node used for transport purposes. Note that the `transport` flag must be set to `rif-comms` (explicitly or by default) for this parameter to be used. Defaults to `"localhost:5013"`. |



4.  After you run lumino command you will be presented with the following message:

```
Welcome to RIF Lumino Payments Protocol, Version 0.1
---------------------------------------------------------------------------------------------------------------
| This is an Alpha version of experimental open source software released under the MIT license. By using the  |
| RIF Lumino Payments Protocol (the “Software”), you acknowledge that this is a test version of the Software  |
| and assume the risk that the Software may contain errors and/or bugs. RIF Labs Limited (“RIF Labs”) makes   |
| no guarantees or representations  whatsoever, including as to the suitability or use of the Software for    |
| any  purpose or regarding its compliance with any applicable laws or regulations. By using the Software,    |
| you acknowledge that you have read this disclosure agreement, understand its contents, and assume all risks |
| related to the use of of the software; further, by answering yes below and accepting the terms of this      |
| Agreement, you release and discharge RIF Labs, its officers, employees, or affiliates from, waive  any      |
| claims you might have against RIF Labs, its officers, employees, or affiliates in connection with, and      |
| agree not to sue RIF Labs or any of its officers, employees, or affiliates for any direct or indirect       |
| liability arising from the use of this Software.                                                            |
|                                                                                                             |
|                                                                                                             |
| Privacy Warning:                                                                                            |
|                                                                                                             |
| By using the RIF Lumino Payments Protocol, you acknowledge that your RSK address, channels, channel deposits|
| settlements, and the RSK address of your channel counterparty will be stored on the RSK blockchain—that is, |
| on servers of RSK node operators—and therefore will be publicly available. The parties running nodes on the |
| RIF Lumino network may also download and store this same or related information or data, and information or |
| data stored on Lumino nodes and  network channels will be publicly visible, including on a RIF Lumino block |
| explorer. By using the Software and by answering yes below, you acknowledge that information or data stored |
| on the Lumino network is extremely difficult to alter, remove, or delete; you further acknowledge that      |
| information or data related to individual tokens transfers will be made available via  the Lumino Payments  |
| Protocol to the recipient intermediating nodes of a specific transfer as well as to the Lumino server       |
| operators.                                                                                                  |
---------------------------------------------------------------------------------------------------------------
Have you read and understood and do you accept the RIF Lumino Disclosure Agreement and Privacy Warning? [y/N]:
```


5. After you accepted you will be asked to select the account you want to use. Select the account and enter your passphrase to continue.


### Contract addresses on each environment


Go to [https://github.com/rsksmart/lumino](https://github.com/rsksmart/lumino) for the updated addresses of the contracts.