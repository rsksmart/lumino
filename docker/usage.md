# Manager

This command is used to execute Lumino modules on docker. 
It provides a way to manage the Lumino infrastructure without the need to know how to use docker.

#### Usage

./manager [FLAGS..]

#### Flags

* *--help* | *-h*: Show this help message.

* *--start*: Build and start the minimal Lumino infrastructure (1 RSK Node, 1 Explorer, 3 Notifiers).

* *--start-modules*: Start a subset of modules inside the Lumino infrastructure, it requires a comma separated list of module names.
    - Example: `./manager --start-modules=rsk-node,lumino-explorer` to start RSK Module only.
    
* *--clean*: It cleans the module images.

* *--clean-all*: It cleans all the docker system (containers, networks, images, etc).

* *--background*: It runs everything in background. You can see the logs using the flag --logs.

* *--logs*: When you run everything on background or you run an specific module you can see the logs using this flag.

* *--connect*: It connects to a module, it requires a module name as a parameter.
    - Example: `./manager --connect=rsk-node`
    
* *--instance-number*: It specifies the instance number to work with, used for flags like --connect.

* *--stop*: It stops everything pulling down all the containers for the Lumino infrastructure.

* *--stop-modules*: Similar to --start-modules, it stop specific containers inside the Lumino infrastructure for specific modules. It requires a comma separated list of module names.
    - Example: `./manager --stop-modules=rsk-node,lumino-explorer`
    
* *--notifiers*: It specifies the number of notifiers to work with with the flags --start and --start-modules. It requires a number as parameter.
    - Example: `./manager --start --notifiers=4`
    
* *--ip*: Shows the ip for all the running modules.

* *--ip-module*: Shows the ip for a specific module. It requires a module name as parameter.
    - Example: `./manager --ip-module=rsk-node`
    
* *--rsk-information*: Shows the rsk network information, contracts, addresses, private keys, etc.

In all the flags the valid module names are: `rsk-node`, `lumino-explorer`, `rif-notifier`
