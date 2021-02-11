### Run the Docker containers

##### Prerequisites

- Linux or macOS
- [Docker](https://docs.docker.com/install/)
- [Docker Compose](https://docs.docker.com/compose/install/)

##### 1. Clone this c-spiffe

```
$ git clone https://github.com/HewlettPackard/c-spiffe.git
$ cd c-spiffe
```

##### 2. Build and run the docker containers

```
$ cd infra/
$ make build

Successfully built
```

Run the containers:

```
$ make run

docker-compose up -d
Creating network "infra_default" with the default driver
Creating infra_spire-server_1 ... done
Creating infra_workload_1     ... done
Creating infra_tests_1        ... done

```

##### 3. Run the SPIRE Server 

On a console run:

```
$ make run-server 

WARN[0000] The configured SVID TTL cannot be guaranteed in all cases - SVIDs with shorter TTLs may be issued if the signing key is expiring soon. Set a CA TTL of at least 6x or reduce SVID TTL below 6x to avoid issuing SVIDs with a smaller TTL than specified 
WARN[0000] Current umask 0022 is too permissive; setting umask 0027 
INFO[0000] Data directory: "./data/server"              
INFO[0000] Opening SQL database            db_type=sqlite3 ubsystem_name=built-in_plugin.sql
INFO[0000] Initializing new database       subsystem_name=built-in_plugin.sql
INFO[0000] Connected to SQL database       read_only=false subsystem_name=built-in_plugin.sqlINFO[0000] plugins started
INFO[0000] Starting gRPC server            subsystem_name=endpoints
INFO[0000] Starting HTTP server            subsystem_name=endpointstype=sqlite3 version=3.25.2
INFO[0000] Plugin loaded                   built-in_plugin=true plugin_name=disk plugin_services="[]" plugin_type=KeyManager subsystem_name=catalog
INFO[0000] Plugin loaded                   built-in_plugin=true plugin_name=join_token plugin_services="[]" plugin_type=NodeAttestor subsystem_name=catalog
INFO[0000] Plugins started
```

##### 4. Create the workloads entries

On a console run:

```
$ make create-entries

+ ./bin/spire-server entry create -parentID spiffe://example.org/host -spiffeID spiffe://example.org/workload -selector unix:uid:1001 -ttl 3600
Entry ID         : 9c11bab7-4fd9-4df2-809f-6ba880411ee8
SPIFFE ID        : spiffe://example.org/workload
Parent ID        : spiffe://example.org/host
Revision         : 0
TTL              : 3600
Selector         : unix:uid:1001

+ ./bin/spire-server entry create -parentID spiffe://example.org/host -spiffeID spiffe://example.org/tests -selector unix:uid:1002 -ttl 3600
Entry ID         : 287c99bc-083a-43c6-b17c-3fc11416b18e
SPIFFE ID        : spiffe://example.org/tests
Parent ID        : spiffe://example.org/host
Revision         : 0
TTL              : 3600
Selector         : unix:uid:1002


```

##### 5. Generate Tokens 

###### 5.1 Generate Agent Token for tests and Run the Agent

On the console run:
```
$ make generate-token SERVICE=tests

Token: 7a7389ac-c841-4c8f-b08b-3cd96b6d9d28
```

Copy the token and run:

```
$ make join-token SERVICE=tests TOKEN={token}

WARN[0000] Current umask 0022 is too permissive; setting umask 0027 
INFO[0000] Starting agent with data directory: "./data/agent" 
INFO[0000] Plugin loaded                  built-in_plugin=true plugin_name=disk plugin_services="[]" plugin_type=KeyManager subsystem_name=catalog
INFO[0000] Plugin loaded                  built-in_plugin=true plugin_name=join_token plugin_services="[]" plugin_type=NodeAttestor subsystem_name=catalog
INFO[0000] Plugin loaded                  built-in_plugin=true plugin_name=unix plugin_services="[]" plugin_type=WorkloadAttestor subsystem_name=catalog
INFO[0000] Bundle is not found            subsystem_name=attestor
DEBU[0000] No pre-existing agent SVID found. Will perform node attestation  path=data/agent/agent_svid.der subsystem_name=attestor
```
##### 6. Clean the environment 

Stop the docker containers:

```
$ make clean

docker-compose down
Stopping infra_tests_1        ... done
Stopping infra_workload_1     ... done
Stopping infra_spire-server_1 ... done
Removing infra_tests_1        ... done
Removing infra_workload_1     ... done
Removing infra_spire-server_1 ... done
Removing network infra_default
```
