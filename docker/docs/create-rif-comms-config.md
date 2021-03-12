## Creating rif-comms configuration file

The rif-comms configuration file has to be something like this:

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
    password: "<YOUR_KEY_PASSWORD_GOES_HERE>",
    openSSL:true,
    privateKeyURLPath:"file:////root/.rif-comms/<YOUR_KEY_FILE_NAME_GOES_HERE>",
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

You can customize everything but be aware that these properties are relative to the docker container.

**IMPORTANT: the config file needs to be saved with name server.json5**