# Get your own RIF Lumino node up and running


![Lumino Network](Lumino.png?raw=true "RIF Lumino Network")


## Technical overview

RIF Lumino Network is an off-chain solution for RSK thats enables near-isntant, low-fee and scalable payments.

RIF Lumino uses a fork of Raiden Network implementation to achieve this.

## Pre requisites

1. Access to a synched RSK node. You can do this in a variety of ways:
   * Run your own node on TestNet or MainNet, see [https://github.com/rsksmart/rskj/wiki/Install-RskJ-and-join-the-RSK-Orchid-Mainnet-Beta]()
   * Compile and run a RSK node locally, see [https://github.com/rsksmart/rskj/wiki/Compile-and-run-a-RSK-node-locally]()
2. RSK account with RBTC balance
3. Linux OS
4. Python 3.6
5. Pip
6. Virtualenv


## Build RIF Lumino from code

1. Get the [RELEASE.NUMBER] code from [GITHUB.URL]
2. Go to the path you downloaded or cloned Lumino's code (let's call this path `$RIF_LUMINO_PATH`)
3. Create python virtual env for RIF Lumino (this has to be made one time)

```virtualenv -p <PATH_TO_PYTHON3.6> clientEnv```

**Note 1:**
Replace `<PATH_TO_PYTHON3.6>` for the path where Python3.6 is installed in your system, in the case of Ubuntu this usually is on path `/usr/bin/python3.6`

**Note 2:**
If you receive an error, please check ***Additional Help*** section.

4. Activate python virtual env

```source clientEnv/bin/activate```

5. Check if your Python version is correct inside the virtual environment

Run:

```python --version```

This command should output version 3.6.x

6. Install RIF Lumino requirements

Inside the virtual environment run the following command:

```pip install -c constraints.txt --upgrade -r requirements-dev.txt ```

7.  Run Lumino setup

```python setup.py develop```

## Start your RIF Lumino Node

1. Go to `$RIF_LUMINO_PATH`
2. If you haven't, execute: `source clientEnv/bin/activate`
3. Run the following command:

```
lumino
    --keystore-path $KEYSTORE_PATH
    --network-id 31
    --eth-rpc-endpoint $RSK_NODE_URL
    --environment-type development
    --tokennetwork-registry-contract-address=$TOKENNETWORK_REGISTRY_CONTRACT_ADDRESS
    --secret-registry-contract-address=$SECRET_REGISTRY_CONTRACT_ADDRESS
    --endpoint-registry-contract-address=$ENDPOINT_REGISTRY_CONTRACT_ADDRESS
    --no-sync-check
    --api-address=127.0.0.1:5001
    --rnsdomain $YOUR_RNS_DOMAIN
    --discoverable  #If this flag is present, then your node will be registered on Lumino Explorer
```

| FIELD                                   | DESCRIPTION                                                                |
|-----------------------------------------|----------------------------------------------------------------------------|
| `$KEYSTORE_PATH`                          | The path to your keystore                                                  |
| `$RSK_NODE_URL`                           | URL of your RSK node (http://URL:PORT)                                     |
| `$TOKENNETWORK_REGISTRY_CONTRACT_ADDRESS` | Address for the token registry contract deployed (view contracts table)    |
| `$SECRET_REGISTRY_CONTRACT_ADDRESS`       | Address for the secret registry contract deployed (view contracts table)   |
| `$ENDPOINT_REGISTRY_CONTRACT_ADDRESS`     | Address for the endpoint registry contract deployed (view contracts table) |
| `$YOUR_RNS_DOMAIN`     | RNS address associated with your rsk node address. i.e: --rnsdomain=lumino.rsk.co |



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


5.  After you accepted, you will be asked to select the account you want to use for your node. Select the account, and enter your passphrase to continue

If start up succeeds you will see the following message:
```
The Lumino API RPC server is now running at http://localhost:5001/.
```
After that you can start interacting with your Lumino nodein any of the two possible ways, both using the REST API and through the UI.

To start using the Lumino Web UI just open your browser at `localhost:5001`.

In order to interact using the REST API, you can use the following Postman collection: https://documenter.getpostman.com/view/5518834/S11PrGM6



### Lumino Contracts

The following are the addresses of the set of contracts for Lumino Network

| Contract                                | TestNet                                    | MainNet        |
|-----------------------------------------|--------------------------------------------|----------------|
| `$TOKENNETWORK_REGISTRY_CONTRACT_ADDRESS` | 0xa494FC762181fF78Fe4CBB75D8609CCff1E63c1B | 0x59eC7Ced1e1ee2e4ccC74F197fB680D8f9426B96  |
| `$SECRET_REGISTRY_CONTRACT_ADDRESS`       | 0xFd17D36EF2b3C5E71aBA059b3FC361644206213b | 0x4Dea623Ae7c5cb1F4aF9B46721D9a72d93C42BE9  |
| `$ENDPOINT_REGISTRY_CONTRACT_ADDRESS`     | 0xb048Af6c0FBFBF1c0c01Ea9A302987011153dbB8 | 0x7d1E6f17baa2744B5213b697ae4C1D287bB10df0 |


## Additional help

The following sections are created using an Ubuntu 16.04.6


### Install Python 3.6



Add a new repository to your APT:

```sudo add-apt-repository ppa:jonathonf/python-3.6```

Update your local APT repository:

```sudo apt-get update```

Install Python 3.6:

```sudo apt-get install python3.6```

### Install PIP3

If you didn't, update your local APT repository:

```sudo apt update```

Install pip3:

```sudo apt-get install python3-pip```

### Install virtualenv

If you didn't, update your local APT repository:

```sudo apt update```

Install virtualenv:

```sudo apt-get install virtualenv```

### Error when we try to create python virtualenv

If you get an error, when you run the `virtualenv -p ...` command, similar to the following one:

```
Original exception was:
Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/virtualenv.py", line 2363, in <module>
    main()
  File "/usr/lib/python3/dist-packages/virtualenv.py", line 719, in main
    symlink=options.symlink)
  File "/usr/lib/python3/dist-packages/virtualenv.py", line 988, in create_environment
    download=download,
  File "/usr/lib/python3/dist-packages/virtualenv.py", line 918, in install_wheel
    call_subprocess(cmd, show_stdout=False, extra_env=env, stdin=SCRIPT)
  File "/usr/lib/python3/dist-packages/virtualenv.py", line 812, in call_subprocess
    % (cmd_desc, proc.returncode))
OSError: Command /root/lumino/clientEnv/bin/python3.6 - setuptools pkg_resources pip wheel failed with error code 1
```

You can solve it executing:

```
export LC_ALL="en_US.UTF-8"
export LC_CTYPE="en_US.UTF-8"
```

### Error installing requirements

If you receive an error, when you're installing Lumino requirements, try this procedure:

1. Exit the virtual environment using `deactivate` command
2. Remove clientEnv folder: `rm -rf clientEnv`

Install the package you need, and restart from the step 3 of the main process.

**If you receive the error: `Command "python setup.py egg_info" failed with error code 1 in /tmp/pip-install-3qvhi58l/psycopg2/`**

Install python3.6-dev package and try again. To install that package you should run:

```sudo apt-get install libpq-dev python3.6-dev```


**If you receive the error: `Command "python setup.py egg_info" failed with error code 1 in /tmp/pip-install-4ceg89vs/psycopg2/`**

Install psycopg2 running:

```pip3 install psycopg2```


## Useful Links

* [RIF Lumino Network](https://www.rifos.org/rif-lumino-network/)
* [RIF Lumino Explorer](http://explorer.lumino.rifos.org/)