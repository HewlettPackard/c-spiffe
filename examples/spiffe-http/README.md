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


# HTTP over mTLS

This example shows how two services using HTTP can communicate using mTLS with X509 SVIDs obtained from SPIFFE workload API.

Each service is connecting to the Workload API to fetch its identities. Since this example assumes the SPIRE implementation, it uses the SPIRE default socket path: `/tmp/agent.sock`. 

```C++
    workloadapi_X509Source *x509source = workloadapi_NewX509Source(NULL, &err);
    if(err != NO_ERROR) {
        printf("workloadapi_NewX509Source() failed: error %u\n", err);
        exit(-1);
    }
    err = workloadapi_X509Source_Start(x509source);
    if(err != NO_ERROR) {
        printf("workloadapi_X509Source_Start() failed: error %u\n", err);
        exit(-1);
    }
```

When the socket path is not provided, the value from the `SPIFFE_ENDPOINT_SOCKET` environment variable is used.

The **HTTP server** uses the `SSL *` to handle the connection, thus creating the HTTP server.

```C++
    SSL *conn = spiffetls_ListenWithMode(port, mode, &config, &sock_fd, &err);

    if(err != NO_ERROR) {
        printf("spiffetls_ListenWithMode() failed: error %u\n", err);
    } else {
        handleConnection(conn);
        const int fd = SSL_get_fd(conn);
        SSL_shutdown(conn);
        SSL_free(conn);
        close(fd);
        close(sock_fd);
    }
```
	
On the other side, the **HTTP client** uses CURL to create a connection to the HTTP server.

```C++
    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, "https://localhost");
    curl_easy_setopt(curl, CURLOPT_PORT, 8443);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_function);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_SSLCERT, cert_filename);
    curl_easy_setopt(curl, CURLOPT_SSLKEY, key_filename);
    curl_easy_setopt(curl, CURLOPT_CAINFO, ca_filename);
```

The [tlsconfig_Authorizer] is used to authorize the mTLS peer. In this example, only server uses it to authorize the specific SPIFFE ID of the other side of the connection.

That is it! The C-spiffe library fetches and automatically renews the X.509 SVIDs of both workloads from the Workload API provider (i.e. SPIRE).

As soon as the mTLS connection is established, the client sends an HTTP request to the server and gets a response.

## Building
To build the client and server workloads:
```bash
cd build/examples/
make
```

## Running
This example assumes the following preconditions:
- There is a SPIRE server and agent up and running.
- There is a Unix workload attestor configured.
- The trust domain is `example.org`
- The agent SPIFFE ID is `spiffe://example.org/host`.
- There is a `server-workload` and `client-workload` user in the system.

### 1. Create the registration entries
Create the registration entries for the client and server workloads:

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
./spiffe_http_server
```

### 3. Run the client
```bash
./spiffe_http_client
```

The server should display a log `Request received` and client `Success!`

If the server workload encounters a peer with a different SPIFFE ID, it will abort the TLS handshake and the connection will fail.

The server log shows

```
spiffetls_ListenWithMode() failed: error 25
```
