## Creating rif-comms configuration file for docker

You need to have a configuration file like this:

```json5
{
  libp2p: {
    addresses: {
      listen: [
        "/ip4/127.0.0.1/tcp/<RPC_PORT>",
        "/ip4/127.0.0.1/tcp/<WS_PORT>/ws"
      ]
    },
    config: {
      peerDiscovery: {
        bootstrap: {
          enabled: false
        }
      }
    }
  },
  loadPrivKeyFromFile: true,
  key : {
    createNew: false,
    password: "<KEY_PASSWORD>",
    openSSL: true,
    privateKeyURLPath:"file:////root/.rif-comms/server.der",
    type: "DER"
  },
  rooms: ["0xtestroom", "0xtestroom6", "0xtestroom3"],
  grpcPort: <GRPC_PORT>,
  displayPeerId: true,
  generatePeerWithSecp256k1Keys: true,
  authorization: {
    enabled: true,
    expiresIn: '1h',
    secret: '',
    challengeSize: 32
  },
  log: {
    level: "debug",
    filter: null,
    path: null
  }
}
```

You can customize everything but be aware that these properties are relative to the docker container, if
you edit the port configuration remember to check if other instances are running on the same ports.

Basically what you need to change on that file are these parameters:

**RPC_PORT**, **WS_PORT** and **GRPC_PORT**, those are generally consecutive, for example 6010, 6011 and 6012, if you want to manage multiple
nodes you need to remember this in order to not use the same ports for more than one server.

**KEY_PASSWORD** is the key password for the key used by the rif-comms server.

**IMPORTANT:** `privateKeyURLPath` property can't be changed since is relative to the container. If you want to change it anyway then 
you need to update the `docker-compose.yml` and change the volume path relative to this key `RIF_COMMS_KEY_FILE:/root/.rif-comms/server.der`
to match your new value.

Here is an example of the config file using ports 6010 (rpc), 6011 (ws) and 6012 (grpc):

```json5
{
  libp2p: {
    addresses: {
      listen: [
        "/ip4/127.0.0.1/tcp/6010",
        "/ip4/127.0.0.1/tcp/6011/ws"
      ]
    },
    config: {
      peerDiscovery: {
        bootstrap: {
          enabled: false
        }
      }
    }
  },
  loadPrivKeyFromFile: true,
  key : {
    createNew: false,
    password: "somepassword",
    openSSL: true,
    privateKeyURLPath:"file:////root/.rif-comms/server.der",
    type: "DER"
  },
  rooms: ["0xtestroom", "0xtestroom6", "0xtestroom3"],
  grpcPort: 6012,
  displayPeerId: true,
  generatePeerWithSecp256k1Keys: true,
  authorization: {
    enabled: true,
    expiresIn: '1h',
    secret: '',
    challengeSize: 32
  },
  log: {
    level: "debug",
    filter: null,
    path: null
  }
}
```