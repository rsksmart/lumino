### How to wire volumes

The basic usage of docker-compose volumes is likes this:

`- <ABSOLUTE_PATH_ON_HOST_MACHINE>:<ABSOLUTE_PATH_ON_GUEST_MACHINE>`

To wire lumino volumes you need to link your host machine files with the already
defined guest files on the `docker-compose.yml` file.

For each service you have something like this:

```yaml
  volumes:
        - "<LUMINO_KEYSTORE_FILE>:/root/.ethereum/keystore/keyfile"
        - "<RIF_COMMS_KEY_FILE>:/root/.rif-comms/server.der"
        - "<RIF_COMMS_CONFIG_FILE>:/root/rif-communications-pubsub-bootnode/config/server.json5"
```

* **LUMINO_KEYSTORE_FILE**: should be the absolute path for your lumino key file. 
(for example: `/home/someuser/.ethereum/keystore/UTC--2020-12-02T15-48-25.457777902Z--c3f056b9cd29c4fc9209bb0f75e71a3360f9ea9f`)


* **RIF_COMMS_KEY_FILE**: should be the absolute path for your rif-comms key file.
(for example: `/home/someuser/.rif-comms/somekey.der`)


* **RIF_COMMS_CONFIG_FILE**: should be the absolute path for your rif-comms configuration file.
(for example: `/home/someuser/workspace/rif-communications-pubsub-bootnode/config/server.json5`)
  

You need to define those parameters for each service you have and make sure that all files are different per service.