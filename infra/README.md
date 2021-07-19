# Infra

This folder contains an orchestration for the integration test scenarios. It is composed by spire-server containers, workload containers, a tests container and some tests scripts.

##### Prerequisites

- Linux or macOS
- [Docker](https://docs.docker.com/install/)
- [Docker Compose](https://docs.docker.com/compose/install/)

##### Clone this c-spiffe

```
$ git clone https://github.com/HewlettPackard/c-spiffe.git
$ cd c-spiffe
```

##### Build docker images locally (optional)
1. Build Spire-server image

```
$ cd infra/spire-server
$ docker build . -t cspiffe/spire-server

Successfully built
```

2. Build Spire-agent image

```
$ cd infra/spire-agent
$ docker build . -t cspiffe/spire-agent

Successfully built
```

3. Build Workload image

Check desired repository url and branch to be pulled inside the image in the Dockerfile. Then run on a console:

```
$ cd infra/workload
$ docker build . -t cspiffe/workload

Successfully built
```

4. Build Tests image

Check desired image tag to be inherited from workload image in the Dockerfile. Then run on a console:

```
$ cd infra/tests
$ docker build . -t cspiffe/tests

Successfully built
```

### Setup for some basic manual tests

##### 1. Run the docker containers

On a console run:

```
$ cd infra/
$ make run TAG=latest

TAG=latest docker-compose up -d
Building with native build. Learn about native build in Compose here: https://docs.docker.com/go/compose-native-build/
Creating infra_spire-server_1  ... done
Creating infra_spire-server2_1 ... done
Creating infra_workload2_1     ... done
Creating infra_workload_1      ... done
Creating infra_tests_1         ... done

```
The tag might be replaced for another one available in [dockerhub](https://hub.docker.com/r/cspiffe/tests/tags?page=1&ordering=last_updated) or locally.

##### 2. Run the SPIRE Server 

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

##### 3. Create the workloads entries

On a console run:

```
$ make create-entries

+ spire-server entry create -parentID spiffe://example.org/myagent -spiffeID spiffe://example.org/myworkload -selector unix:user:root
Entry ID         : ad80a864-935c-40e6-b218-6a2b5b4d6034
SPIFFE ID        : spiffe://example.org/myworkload
Parent ID        : spiffe://example.org/myagent
Revision         : 0
TTL              : default
Selector         : unix:user:root

+ spire-server entry create -parentID spiffe://example.org/host -spiffeID spiffe://example.org/tests -selector unix:uid:1002
Entry ID         : d83795b7-d51d-4297-924a-d5174591ba92
SPIFFE ID        : spiffe://example.org/tests
Parent ID        : spiffe://example.org/host
Revision         : 0
TTL              : default
Selector         : unix:uid:1002

+ spire-server entry create -parentID spiffe://example.org/host -spiffeID spiffe://example.org/tests -selector unix:user:root
Entry ID         : 77b50a95-e374-4a50-8fd5-690d3f023a1d
SPIFFE ID        : spiffe://example.org/tests
Parent ID        : spiffe://example.org/host
Revision         : 0
TTL              : default
Selector         : unix:user:root

```

##### 4. Generate Tokens 

On the console run:
```
$ make generate-token

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

##### 5. Go into the tests container and execute some desired test

##### 6. Clean the environment 

On a console run:

```
$ make clean

docker-compose down
WARNING: The TAG variable is not set. Defaulting to a blank string.
Stopping infra_tests_1         ... done
Stopping infra_workload_1      ... done
Stopping infra_workload2_1     ... done
Stopping infra_spire-server_1  ... done
Stopping infra_spire-server2_1 ... done
Removing infra_tests_1         ... done
Removing infra_workload_1      ... done
Removing infra_workload2_1     ... done
Removing infra_spire-server_1  ... done
Removing infra_spire-server2_1 ... done
Removing network infra_default
```

### Execute all automated integration tests 

On a console run:

```
$ make integration-tests TAG=latest

TAG=latest docker-compose up -d
Building with native build. Learn about native build in Compose here: https://docs.docker.com/go/compose-native-build/
Creating network "infra_default" with the default driver
Creating infra_spire-server2_1 ... done
Creating infra_spire-server_1  ... done
Creating infra_workload_1      ... done
Creating infra_workload2_1     ... done
Creating infra_tests_1         ... done

...

6 features passed, 0 failed, 0 skipped
40 scenarios passed, 0 failed, 0 skipped
466 steps passed, 0 failed, 0 skipped, 0 undefined
Took 15m11.601s
docker-compose down
WARNING: The TAG variable is not set. Defaulting to a blank string.
Stopping infra_tests_1         ... done
Stopping infra_workload2_1     ... done
Stopping infra_workload_1      ... done
Stopping infra_spire-server_1  ... done
Stopping infra_spire-server2_1 ... done
Removing infra_tests_1         ... done
Removing infra_workload2_1     ... done
Removing infra_workload_1      ... done
Removing infra_spire-server_1  ... done
Removing infra_spire-server2_1 ... done
Removing network infra_default
```
The tag might be replaced for another one available in [dockerhub](https://hub.docker.com/r/cspiffe/tests/tags?page=1&ordering=last_updated) or locally.
