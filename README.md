# RIF Lumino Network


![Lumino Network](Lumino.png?raw=true "RIF Lumino Network")


## Install your own Lumino Node

* [Install on Ubuntu](docs/0.1.0/install_ubuntu.md)
* [Install on MacOS](docs/0.1.0/install_macos.md)

## Run with docker

You can run lumino with docker instead of installing everything locally.

* **Pre-requisites**
    * Install docker
    * Install docker-compose
    * Create a config file for rif-comms node to work with docker. [Here is how to do that.](./docker/docs/create-rif-comms-config.md)
    * Have a key for the rif-comms node. [Here is how to create it.](https://github.com/rsksmart/rif-communications-pubsub-bootnode/tree/grpc-api)
    * Have an account created to use with the lumino node.
    
To run lumino on the docker container you have to do these steps:

* Make sure you have all the pre-requisites specified above.
* Locate the folder containing the keystore for your lumino accounts, 
  the folder containing the key and the folder containing the configuration for the rif-comms node.
* Identify the network data necessary for the lumino node to work. That is the token network registry, 
  secret registry and endpoint registry contract addresses, also you need the rsk node endpoint location.
* Open a terminal and move to the docker folder inside this repository.
* Open the file .env there and edit the values to match your environment values, [here](./docker/docs/environment-file.md) we explain the content of that file.
* After you configure the .env file inside the docker folder then save it.
* Now we have 2 ways to do this, the automated way or the manual way:
    * **Manual**:
        * Run `ln -s /folder/where/you/have/lumino/keystore volumes/lumino-keystore`
        * Run `ln -s /folder/where/you/have/rif-comms/key volumes/rif-comms-key`
        * Run `ln -s /folder/where/you/have/rif-comms/config volumes/rif-comms-config`
        * Run `sudo docker-compose build` to build the docker image.
        * Run `sudo docker-compose up -d` to start the lumino container.
        * Run `sudo docker exec -it docker_lumino-node_1 /root/lumino/startLumino` to run lumino and rif-comms nodes.
        * After you finish working with the lumino node you can kill it with Ctrl-C but you need to clean up the links and the
        running container, to do that you need to run:
          * `sudo docker-compose down`
          * `rm -rf volumes/*`
    * **Automated**:
        * You only need to run one command `./startDocker <RIF-COMMS_CONFIG_FOLDER_PATH> <RIF-COMMS_KEY_FOLDER_PATH> <LUMINO_KEYSTORE_FOLDER_PATH>`    
        * The script will do everything for you, create the links for the volumes, start the container and the nodes, also it will cleanup everything if you kill it.
## Lumino Contracts

The following are the addresses of the set of contracts for Lumino Network per release

# Node release 0.0.2

| Contract                                | TestNet                                    | MainNet        |
|-----------------------------------------|--------------------------------------------|----------------|
| `$TOKENNETWORK_REGISTRY_CONTRACT_ADDRESS` | N/A | 0x59eC7Ced1e1ee2e4ccC74F197fB680D8f9426B96  |
| `$SECRET_REGISTRY_CONTRACT_ADDRESS`       | N/A | 0x4Dea623Ae7c5cb1F4aF9B46721D9a72d93C42BE9  |
| `$ENDPOINT_REGISTRY_CONTRACT_ADDRESS`     | N/A | 0x7d1E6f17baa2744B5213b697ae4C1D287bB10df0 |

# Node release 0.0.4


| Contract                                | TestNet                                    | MainNet        |
|-----------------------------------------|--------------------------------------------|----------------|
| `$TOKENNETWORK_REGISTRY_CONTRACT_ADDRESS` | 0x7385f5c9Fb5D5cd11b689264756A847359d2FDc7 | 0x060B81E90894E1F38A625C186CB1F4f9dD86A2B5  |
| `$SECRET_REGISTRY_CONTRACT_ADDRESS`       | 0x59e1344572EC42BB0BB95046E07d6509Bc737b57 | 0xfddac0Ca372877d8E5376A4624F95ADF77B83FE1  |
| `$ENDPOINT_REGISTRY_CONTRACT_ADDRESS`     | 0x6BEb99b6eCac8E4E2EdeC141042135D0dD8F15c1 | 0x150840901Cca6d432B1aaEfD65d6D53b964C7EE5 |

# Node release 1.0.0

| Contract                                | TestNet                                    | MainNet        |
|-----------------------------------------|--------------------------------------------|----------------|
| `$TOKENNETWORK_REGISTRY_CONTRACT_ADDRESS` | 0x47E5b7d85Da2004781FeD64aeEe414eA9CdC4f17 | 0x060B81E90894E1F38A625C186CB1F4f9dD86A2B5  |
| `$SECRET_REGISTRY_CONTRACT_ADDRESS`       | 0xed8c9163F888Bc2f9C4F299325003DA5fC8676DD | 0xfddac0Ca372877d8E5376A4624F95ADF77B83FE1  |
| `$ENDPOINT_REGISTRY_CONTRACT_ADDRESS`     | 0xDbc02f59135811A934A7131A4013411696cE03f4 | 0x150840901Cca6d432B1aaEfD65d6D53b964C7EE5 |


If you want to create your own RIF Lumino network for development or custom use on private networks, please refer to [Lumino Contracts](https://github.com/rsksmart/lumino-contracts)

## Useful Links

* [RIF Lumino Network](https://developers.rsk.co/rif/lumino/)
* [RIF Lumino Contracts](https://github.com/rsksmart/lumino-contracts) 
* [RIF Lumino Web](https://github.com/rsksmart/lumino-web) 
* [RIF Lumino Explorer](https://github.com/rsksmart/lumino-explorer) 
* [RIF Lumino Explorer UI](https://explorer.lumino.rifos.org/)

