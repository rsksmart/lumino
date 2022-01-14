### Running more than 2 node instances

For each new node you want to add you need to follow these steps:

1. Create(or use) an account for lumino and get the key file.
2. Create a key file for the rif-comms server.
3. Create a configuration file for the rif-comms server.
4. Make sure that the ports you choose on the configuration file are not being used.
5. Under the directory environment add a new file called `node<SERVICE_NUMBER>.env` with the 
   environment variables for that service. `<SERVICE_NUMBER>` is arbitrary, you can call the file
   like you want, just remember the name to link that later on the `docker-compose.yml` file.
5. Edit the `docker-compose.yml` file to add the new service like this:

```yaml
version: "2.2"

services:

    lumino-node-1:
        build: "."
        env_file:
          - "environment/node1.env"
        restart: "no"
        network_mode: "host"
        volumes:
          - "<LUMINO_KEYSTORE_FILE>/root/.ethereum/keystore/keyfile"
          - "<RIF_COMMS_KEY_FILE>:/root/.rif-comms/server.der"
          - "<RIF_COMMS_CONFIG_FILE>:/root/rif-communications-pubsub-bootnode/config/server.json5"

    lumino-node-2:
      build: "."
      env_file:
        - "environment/node2.env"
      restart: "no"
      network_mode: "host"
      volumes:
        - "<LUMINO_KEYSTORE_FILE>/root/.ethereum/keystore/keyfile"
        - "<RIF_COMMS_KEY_FILE>:/root/.rif-comms/server.der"
        - "<RIF_COMMS_CONFIG_FILE>:/root/rif-communications-pubsub-bootnode/config/server.json5"
  
    lumino-node-3: # the new service being added
      build: "."
      env_file:
        - "environment/node<SERVICE_NUMBER>.env"
      restart: "no"
      network_mode: "host"
      volumes:
        - "<LUMINO_KEYSTORE_FILE>/root/.ethereum/keystore/keyfile"
        - "<RIF_COMMS_KEY_FILE>:/root/.rif-comms/server.der"
        - "<RIF_COMMS_CONFIG_FILE>:/root/rif-communications-pubsub-bootnode/config/server.json5"
```

Fill the values `<LUMINO_KEYSTORE_FILE>`, `<RIF_COMMS_KEY_FILE>` and `<RIF_COMMS_CONFIG_FILE>` with
the absolute paths of the files.

You have successfully added a new service that will create a container 
with lumino and rif-comms servers inside. The next time you run `sudo docker-compose up -d` 
it will start the new container.

**IMPORTANT: you need to be careful with the port numbers you use on the environment and configuration
files to avoid having port conflict issues when you start all the services, keep in mind all
these services are running in localhost context.**