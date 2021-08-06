<!--
(C) Copyright 2020-2021 Hewlett Packard Enterprise Development LP

 

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

 

    http://www.apache.org/licenses/LICENSE-2.0

 

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.

-->


# Run go-echo-server

A mTLS echo server/client in Go.

##### Prerequisites

- Linux or macOS
- [Docker](https://docs.docker.com/install/)
- [Docker Compose](https://docs.docker.com/compose/install/)
- [OpenSSL](https://www.openssl.org/docs/) (Only if new certificates are needed)
- [Make (4.2.1-1.2)](https://www.gnu.org/software/make/)

##### 1. Clone this c-spiffe

```
$ git clone https://github.com/HewlettPackard/c-spiffe.git
$ cd c-spiffe
```
##### 2. Generate the certs

This step just needs to be done once. (Certificates already exist in the repo, so this step can be skipped.)

```
$ cd integration_test/helpers/go-echo-server/certs
$ ./cert-generator.sh

    make server cert
    Generating a RSA private key
    ........................................+++++
    ......+++++
    writing new private key to 'server.key'
    -----
    req: No value provided for Subject Attribute emailAddress, skipped
    make client cert
    Generating a RSA private key
    ........+++++
    .......+++++
    writing new private key to 'client.key'
    -----
    req: No value provided for Subject Attribute emailAddress, skipped
```

##### 3. Build and run the docker containers

```
$ cd c-spiffe/infra/
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

##### 4. Run the Echo Server 

```
$ docker exec -it infra_workload_1 bash
```
Inside workload container, run:

```
$ root@workload: cd /mnt/c-spiffe/integration_test/helpers/go-echo-server/server
$ root@workload: go run server.go

    2021/04/07 12:14:41 server: listening on port 8000
```

##### 5. Run the Client

On a new console, run:

```
$ docker exec -it infra_tests_1 bash
```
Inside tests container, run:

```
$ root@tests: cd /mnt/c-spiffe/integration_test/helpers/go-echo-server/client
$ root@tests: go run client.go "any message (max 100 bytes)"

    2021/04/07 12:23:01 client: connected to:  172.24.0.3:8000
    2021/04/07 12:23:01 client: handshake:  true
    2021/04/07 12:23:01 client: mutual:  true
    2021/04/07 12:23:01 client: sent     "any message (max 100 bytes)" (27 bytes)
    2021/04/07 12:23:01 client: received "any message (max 100 bytes)" (27 bytes)
    2021/04/07 12:23:01 client: exiting
```

##### 6. Stop the containers

On a new console, run:

```
$ cd /mnt/c-spiffe/infra
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
