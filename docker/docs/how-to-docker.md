## How to run lumino with docker

#### Pre-requisites
1. Install docker
2. Install docker-compose
3. Create a configuration file for rif-comms server to work with docker **[1]**.
  [Here is how to do that.](create-rif-comms-config.md)
4. Have a key for the rif-comms server. [Here is how to create it.](https://github.com/rsksmart/rif-communications-pubsub-bootnode/tree/grpc-api). **[1]**
5. Have an account to use with lumino (locate the key file in your host machine, 
   usually that file is located under the home folder at
  `.ethereum/keystore`). **[1]**
    
#### Running docker

To run lumino on the docker container you have to follow these steps:

1. Make sure you have all the [pre-requisites](Pre-requisites) specified above.
2. Locate key files for lumino and rif-comms servers (absolute paths).
3. Locate configuration file for the rif-comms server (absoute path).
4. Identify the necessary chain data to run lumino node. That is the token network registry, 
  secret registry and endpoint registry contract addresses, the chain id and rsk node endpoint location.
5. Open a terminal and move to the docker folder inside this repository.
6. There, locate the folder environment where you have all the environment files for your nodes, 
   by default we have 2, but we can have more.
  Open the file `node1.env` to configure your first node. Edit the values to match your environment 
   values, we explain the content of that file [here](environment-file.md).
   You have to do the same thing for each node you want to run, so you need to do the same for 
   `node2.env`. To run more than 2 nodes you can review [this](running-more-than-2-nodes.md).
7. After you finish with the .env files inside the environment folder then save the changes.
8. Now you have to update your `docker-compose.yml` file where you will describe 
   the lumino node services, wire the environment files updated above and
   bind the volumes with the real files in your host machine. [Here is how to do it](how-to-wire-volumes.md)
  
9. Now you need to run these commands to get everything up and running:
    * Run `sudo docker-compose build` to build the docker image.
    * Run `sudo docker-compose up -d` to start the lumino containers.
    * Run `sudo docker exec -it <CONTAINER_ID> /root/lumino/startLumino` to run lumino and 
      rif-comms nodes. The `CONTAINER_ID` can be retrieved running `sudo docker ps`, that will show all
      the running containers. Basically docker does this 
      `CONTAINER_ID=(BASE_FOLDER_NAME)_(SERVICE_NAME)_(INSTANCE_NUMBER)`. Taking that as the base naming rule
      you can see that our docker container for our first server could be `docker_lumino-node-1_1` and for our
      second server will be `docker_lumino-node-2_1`. That's because `docker` is the base folder name where we are deploying,
      `lumino-node-1` and `lumino-node-2` are our services and the last number is the instance number of the running service.
    * After you finish working with the servers you can kill them with Ctrl-C, but you need to clean up the
        running containers, to do that you need to run `sudo docker-compose down`. In case you want to kill only 
      one lumino container, then you can do that by using `sudo docker kill <CONTAINER_ID>`.
      

**[1]: do the action for each server you want to run**