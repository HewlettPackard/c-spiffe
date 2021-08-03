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


# Mutually Authenticated TLS (mTLS)

This example shows how to use the C-spiffe library to establish a mTLS connection between two workloads using X.509 SVIDs obtained from the SPIFFE Workload API. 

One workload acts as a client and the other as the server. 

The scenario goes like this:
1. The server starts listening for incoming SPIFFE-compliant mTLS connections.
2. The client establishes an SPIFFE-compliant mTLS connection to the server. 
3. The server starts waiting for a message from the client.
4. The client sends a "Hello server" message and starts waiting for a response.
5. The server reads the client's message, logs it to stdout, and sends a "Hello client" message as the response.
6. The client reads the server's response and then closes the connection.

## Listening
To start listening for incoming connections the **server workload** uses the [spiffetls_ListenWithMode] function as follows:
```C++
    SSL *conn
        = spiffetls_ListenWithMode(port, mode, &config, &sock_fd, &err);
```
Where:
- port is the port (`55555U`) where the server workload is going to listen for client connections.
- [spiffetls_MTLSServerWithSource] is used to configure the [workloadapi_X509Source] used by the internal Workload API client.
- config is a preset variable if the user wishes to use a pre-configured `SSL_CTX` and/or an already created, binded and listening socket. `NULL` and a nonpositive integer are the default values, respectively. In this case, the function will configure a `SSL_CTX` variable and create a socket internally.
- sock_fd is the variable where the server socket will be returned. It must be closed when no longer needed.

## Dialing
To establish a connection, the **client workload** uses the [spiffetls_DialWithMode] function as follows:
```C++
    SSL *conn = spiffetls_DialWithMode(port, addr, mode, &config, &err);
```
Where:
- port is the port (`55555U`) where the client workload is going to dial for server connections.
- addr is the address (`0x7F000001U`, 127.0.0.1 - localhost) where the client workload is going to dial for server connections.
- [spiffetls_MTLSClientWithSource] is used to configure the [workloadapi_X509Source] used by the internal Workload API client.
- config is a preset variable if the user wishes to use a pre-configured `SSL_CTX` and/or an already created and connected socket. `NULL` and a nonpositive integer are the default values, respectively. In this case, the function will configure a `SSL_CTX` variable and create a socket internally.

## That is it!
As we can see the C-spiffe library allows your application to use the Workload API transparently for both ends of the connection. The C-spiffe library takes care of fetching and automatically renewing the X.509 SVIDs needed to maintain a secure communication.

## Building
To build the client and server workloads:
```bash
cd build/examples/
make
```

## Running
This example assumes the following preconditions:
- There is a SPIRE server and a SPIRE agent up and running.
- There is a Unix workload attestor configured.
- The trust domain is `example.org`.
- The agent's SPIFFE ID is `spiffe://example.org/host`.

### 1. Create the registration entries
Create the registration entries for the workloads:

Server:
```bash
spire-server entry create -spiffeID spiffe://example.org/server \
                          -parentID spiffe://example.org/host \
                          -selector unix:user:root
```

Client: 
```bash
spire-server entry create -spiffeID spiffe://example.org/client \
                          -parentID spiffe://example.org/host \
                          -selector unix:user:root
```

### 2. Start the server
```bash
./spiffe_tls_server
```

### 3. Run the client
```bash
./spiffe_tls_client
```

The server should have received a _"Hello server"_ message and responded with a _"Hello client"_ message.
