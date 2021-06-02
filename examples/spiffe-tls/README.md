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
- [spiffetls_MTLSServerWithSource] is used to configure the [X509Source] used by the internal Workload API client.
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
- [spiffetls_MTLSClientWithSource] is used to configure the [X509Source] used by the internal Workload API client.
- config is a preset variable if the user wishes to use a pre-configured `SSL_CTX` and/or an already created and connected socket. `NULL` and a nonpositive integer are the default values, respectively. In this case, the function will configure a `SSL_CTX` variable and create a socket internally.

## That is it!
As we can see the C-spiffe library allows your application to use the Workload API transparently for both ends of the connection. The C-spiffe library takes care of fetching and automatically renewing the X.509 SVIDs needed to maintain a secure communication.

## Building
To build the client workload:
```bash
cd build/examples/spiffe-tls/client
make
```

To build the server workload:
```bash
cd build/examples/spiffe-tls/server
make
```

## Running
This example assumes the following preconditions:
- There is a SPIRE server and a SPIRE agent up and running.
- There is a Unix workload attestor configured.
- The trust domain is `example.org`.
- The agent's SPIFFE ID is `spiffe://example.org/host`.
- There is a `server-workload` user and a `client-workload` user in the system.

### 1. Create the registration entries
Create the registration entries for the workloads:

Server:
```bash
./spire-server entry create -spiffeID spiffe://example.org/server \
                            -parentID spiffe://example.org/host \
                            -selector unix:user:server-workload
```

Client: 
```bash
./spire-server entry create -spiffeID spiffe://example.org/client \
                            -parentID spiffe://example.org/host \
                            -selector unix:user:client-workload
```

### 2. Start the server
Start the server with the `server-workload` user:
```bash
sudo -u server-workload ./server
```

### 3. Run the client
Run the client with the `client-workload` user:
```bash
sudo -u client-workload ./client
```

The server should have received a _"Hello server"_ message and responded with a _"Hello client"_ message.

If either workload encounters a peer with a different SPIFFE ID than the one it expects, the workload aborts the TLS handshake and the connection fails.  
For instance, when running the client with the server's user: 
```
sudo -u server-workload ./client

Unable to read server response: remote error: tls: bad certificate
```

The server log would contain:
```
Error reading incoming data: unexpected ID "spiffe://example.org/server"
```