# supra-xrbc-coi
Application utilising Supra xRBC and Chain of Integrity protocols

Features:
- Batch deliver implementation according to X-RBC protocol
- Simulated batch-creation
- Simulated batch-delivery consumption
- Simulate fault node

# Configure host environment for simulation

Before starting simulation locally or remotely host environment should be configured by creating .env file and initializing the following variables
```
INSTANCE_KEY="absolute path to instance key"
INSTANCE_KEY_NAME="name of instance key"
INSTANCE_NAME="Name of ec2 instance (unique identifier)"
INSTANCE_SECURITY_GROUP="Name of instance security group (unique identifier)"
GITHUB_DEPLOY_KEY_PATH="path to github deployment key"
CHAIN_PARAMETER="chain_parameters.json" # chain parameters to start simulation
FAULT_PERCENT=20 # ceil of 20 percent per clan
PASSIVE_OR_CRASHED=0 # 0 indicates PASSIVE node does not react on normal xRBC messages except sync message, 1 indicates that nodes are crushed.
GIT_BRANCH="master" # branch to be used for remote runs
DURATION=10 # duration of the simulation

# If the InfluxDB environment variable is not set then the metric logger will
# use no registry as default metric logger
# To enable influxdb metrics db configuration in scope of the node
# Otherwise do not specify any of the parameters
# Make sure host address in correct url. Empty orinvalid url causes panic
INFLUXDB_HOST="http://localhost:8086"
INFLUXDB_TOKEN="==token=="
# Make sure that orgnization exists to have influx backend connection 
# properly configured
INFLUXDB_ORG="supraoracles"
INFLUXDB_BUCKET="xrbc-coi"
```

# Python fabric command description

| Command |Description|
|---------|-----------|
|build        | Build source on AWS |
|create       | Start required aws instances according to the chain parameter  |
|destroy      | Destroy the testbed |
|info         | Display connect information about all the available machines |
|install      | Install the codebase on all machines |
|local        | Run chain on localhost |
|log          | Download Logs |
|remote       | Run the experiment on AWS and download the logs |
|reset        | reset instance key |
|start        | Start at most `max` machines per data center |
|stop         | Stop all machines |
|stop-nodes   | Stop any running nodes on remote instances |


To query the available aws instance one can always run ``fab info`` command

# How To Start chain locally using startup scripts

fab command line tool is used to develop startup script/task to start chain locally and remotely.<BR>
The scripts are located under `scripts` folder.<BR>

To prepare environment(one time operation):
```shell
cd scripts
pip3 install -r requirements.txt
sudo apt install fabric
```
To run chain locally:
```shell
fab local
# compiles the supra-node
# generates chain configuration files (identity files, peer details, chain parameters)
# start the chain nodes
# waits for 30 seconds and stops all nodes
```
Uses default chain parameters at `scripts/chain_parameters.json` to start chain network

```shell
> fab local -h
Usage: fab [--core-opts] local [--options] [other tasks here ...]

Docstring:
  Run chain on localhost

Options:
  -c STRING, --chain-parameters=STRING
  -d INT, --duration=INT
  -e, --debug
  -r, --reuse
  -y, --dry-run

```

To start chain with custom chain parameters:
```shell
> fab local -c custom_chain_parameters.json
```

To start chain with custom runtime duration(120) in seconds
```shell
> fab local -d 120
```

To start chain with debug logging level enabled (default is info)
```shell
> fab local -e
```

To start chain reusing previously generated chain configuration parameters
```shell
> fab local -r
```

To run flow without starting nodes
```shell
> fab local -y
```

# How to start chain remotely

Once the local run is configured then starting the chain remotely requires [configuring AWS cli](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html) followed by
the following command in scope of `scripts` directory.

- `fab create` : Start required aws instances according to the chain parameter
- `fab install` : Clone the `supra-xrbc-coi` repository into each instances
- `fab build` : Build the cargo project

After above steps remote instances are ready to start the chain remotely using command `fab remote`.
When remote run is done in scope of logs directory one can locate simulation logs per instance.

When experiments are done it is mandatory to bring the instances down by running `fab destroy`.

To query the available aws instance one can always run ``fab info`` command

# Run experiment and deduce Metrics

Remote experiment can be run using `experiment.sh` bash script followed by `report.py` python script which will generate reports for the experiment
The reports are generated and dumped with csv format:

- delivery_metrics.csv  - latency metrics
- size_metrics.csv - message size metrics
- throughput_metrics.csv   - input and output throughput
- time_metrics.csv - message travel time metrics


# Supra Node CLI and startup

## How to build
```shell
> cd _supra_xrbc_coi_source_directory
> cargo build --release
```

## Supra-Node Command line interface

supra-node supports 3 main commands

| Command |Description|
|---------|-----------|
| run| starts the node with provided input configurations|
| generate | generates random identities for nodes of the configured chain and random topology of the chain|
| dump | dumps default chain-parameter configuration in json format|

```shell
Usage: supra-node [OPTIONS] <COMMAND>

Commands:
  run       Starts node with the input configurations
  dump      Dumps default chain parameters to file
  generate  Generates and dumps random topology in terms of peers details and node identities based on the input network configuration
  help      Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose...  Level of verbosity, the higher the number of "v"s the higher the level
  -h, --help        Print help information

```

### Run Supra Node
```shell
> ./supra-node run <CHAIN_PARAM_FILE> <IDENTITY_CONFIG> <PEERS_CONFIG> # with error logging level
> ./supra-node -v run <CHAIN_PARAM_FILE> <IDENTITY_CONFIG> <PEERS_CONFIG> # with warn logging level
> ./supra-node -vv run <CHAIN_PARAM_FILE> <IDENTITY_CONFIG> <PEERS_CONFIG> # with info logging level
> ./supra-node -vvv run <CHAIN_PARAM_FILE> <IDENTITY_CONFIG> <PEERS_CONFIG> # with debug logging level
```

```shell

> ./supra-node run --help
Starts node with the input configurations

Usage: supra-node run <CHAIN_PARAM_FILE> <IDENTITY_CONFIG> <PEERS_CONFIG>

Arguments:
  <CHAIN_PARAM_FILE>  Full path to chain configuration parameters file
  <IDENTITY_CONFIG>   Full path to node identity config
  <PEERS_CONFIG>      Full path to peers detailed config

Options:
  -h, --help  Print help information

```

CHAIN_PARAM_FILE contains chain configuration parameters in terms of
- network layout
- committee/clan distributed key configuration
- batch proposing configuration properties
- X-RBC delivery configuration parameters in terms of deliverable data sharding configuration parameters

Example of chain-configuration parameters for chain with 625 nodes and 125 committee/clan size<BR>
with 62 committee fault tolerance and 208 total chain fault tolerance:
```json
{
  "network_config": {
    "tribes": 1,
    "clans": 5,
    "clan_size": 125,
    "proposers_per_tribe": 1,
    "proposers_per_clan": 5
  },
  "dkg_config": {
    "threshold": 63,
    "participants": 125
  },
  "batch_config": {
    "timeout_in_secs": 10,
    "size_in_bytes": 5000000
  },
  "delivery_config": {
    "Rs16": {
      "committee_erasure_config": {
        "data_shards": 63,
        "parity_shards": 62
      },
      "network_erasure_config": {
        "data_shards": 293,
        "parity_shards": 208
      }
    }
  }
}
```
Example of chain-configuration parameters for chain with single clan/committee
```json
{
  "network_config": {
    "tribes": 1,
    "clans": 1,
    "clan_size": 125,
    "proposers_per_tribe": 1,
    "proposers_per_clan": 5
  },
  "dkg_config": {
    "threshold": 63,
    "participants": 125
  },
  "batch_config": {
    "timeout_in_secs": 10,
    "size_in_bytes": 5000000
  },
  "networking_config": {
    "xrbc_port": 3050
  },
  "delivery_config": {
    "Rs16": {
      "committee_erasure_config": {
        "data_shards": 63,
        "parity_shards": 62
      },
      "network_erasure_config": null
    }
  }
}
```

IDENTITY_CONFIG contains nodes secrete and public key raw information.<BR>
Currently ED25519 PublicKey pair is supported.
```json

{
  "key_pair": [
    225, 15, 38, 154, 41, 8, 46, 154, 151, 236, 213, 196, 6, 67, 67, 201, 42, 86, 56, 189, 186, 62, 161, 236, 248,
    184, 243, 101, 99, 142, 176, 39, 75, 188, 108, 25, 13, 236, 93, 39, 62, 149, 42, 148, 193, 92, 58, 222, 231, 118,
    233, 62, 125, 220, 28, 52, 165, 129, 175, 40, 29, 126, 157, 48
  ]
}
```

PEERS_CONFIG contains list of all peers details, which includes peer
- position and role in chain
- ip address & port
- peer public-key as peer unique identifier

This is useful unless chain-bootstrap/election logic is incorporated.

Example of peer detailed information:
```json
  {
    "id": [
      116, 73, 121, 65, 7, 206, 58, 155, 85, 130, 253, 159, 173, 74, 51, 113, 229, 37, 124,
      175, 160, 122, 25, 211, 220, 239, 92, 178, 129, 190, 89, 165
    ],
    "address": "127.0.0.1",
    "port": 3051,
    "position": 1,
    "clan": 0,
    "tribe": 0,
    "role": "Leader"
  }
```

## Generating chain configurations
```shell
# to generate identities and detailed peer info for local run
> ./supra-node generate <NETWORK_CONFIG_FILE> <DESTINATION> <FAULT_PERCENT>
# to generate identities and detailed peer info for remote run
> ./supra-node generate <NETWORK_CONFIG_FILE> <DESTINATION> <FAULT_PERCENT> <REMOTE_IPS>

```
```shell

> ./supra-node generate --help
Generates and dumps random topology in terms of peers details and node identities based on the input network configuration

Usage: supra-node generate <NETWORK_CONFIG_FILE> <DESTINATION> <FAULT_PERCENT> [REMOTE_IPS]

Arguments:
  <NETWORK_CONFIG_FILE>  Full path to network configuration parameters file
  <DESTINATION>          Full path to destination directory
  <FAULT_PERCENT>        Percentage of faulty node present in experiment chain
  [REMOTE_IPS]           Full path to remote ip addresses if configs are for remote run

Options:
  -h, --help  Print help information
```

NETWORK_CONFIG_FILE contains configuration parameters related to chain layout:
- number of tribes in chain
- number of clans in a tribe
- number of peers in a clan
- number of proposer/leader clans in a tribe
- number of proposers/leaders in a proposer clan

Example of the network config file:
```json
{
  "tribes": 1,
  "clans": 1,
  "clan_size": 125,
  "proposers_per_tribe": 1,
  "proposers_per_clan": 5
}
```

DESTINATION is the directory path where generated files are resided.

REMOTE_IPS is an optional configuration file, and used when chain is aimed to started remotely.
It is expected to have unique remote ips in the REMOTE_IPS config file equal to the total number of nodes.

As a result for each node `node_&lt;tribe&gt;_&lt;clan&gt;_&lt;position&gt;[_&lt;ip&gt;].json` file containing<BR>
random identity is generated, along with chain-random-topology is dumped in form of peers-details in `peers.json` file

Example of the DESTINATION folder:
```shell
> ls configs/ -ll
total 9
-rwxrwx--- 1 areg plugdev  762 Dec 21 13:46 chain_parameters.json
-rwxrwx--- 1 areg plugdev  114 Dec 21 13:46 network_config.json
-rwxrwx--- 1 areg plugdev  572 Dec 21 13:46 node_0_0_0.json
-rwxrwx--- 1 areg plugdev  568 Dec 21 13:46 node_0_0_1.json
-rwxrwx--- 1 areg plugdev  570 Dec 21 13:46 node_0_0_2.json
-rwxrwx--- 1 areg plugdev  569 Dec 21 13:46 node_0_0_3.json
-rwxrwx--- 1 areg plugdev  578 Dec 21 13:46 node_0_0_4.json
-rwxrwx--- 1 areg plugdev    2 Dec 21 13:46 faulty_peers.txt
-rwxrwx--- 1 areg plugdev 2412 Dec 21 13:46 peers.json

> ls configs_remote/ -ll
total 9
-rwxrwx--- 1 areg plugdev  762 Dec 21 13:46 chain_parameters.json
-rwxrwx--- 1 areg plugdev  114 Dec 21 13:46 network_config.json
-rwxrwx--- 1 areg plugdev  579 Dec 21 13:51 node_0_0_0_192.168.1.14.json
-rwxrwx--- 1 areg plugdev  571 Dec 21 13:51 node_0_0_1_192.168.1.12.json
-rwxrwx--- 1 areg plugdev  568 Dec 21 13:51 node_0_0_2_192.168.1.13.json
-rwxrwx--- 1 areg plugdev  573 Dec 21 13:51 node_0_0_3_192.168.1.10.json
-rwxrwx--- 1 areg plugdev  571 Dec 21 13:51 node_0_0_4_192.168.1.11.json
-rwxrwx--- 1 areg plugdev    2 Dec 21 13:51 faulty_peers.txt
-rwxrwx--- 1 areg plugdev 2423 Dec 21 13:51 peers.json
```
