# Authenticating Workloads over TLS-encrypted HTTP Connections Using JWT-SVIDs

This example shows how to use the C-spiffe library to make a server workload authenticate a client workload using JWT-SVIDs fetched from the Workload API. 

JWT-SVIDs are useful when the workloads are not able to establish an mTLS communication channel between each other. For instance, when the server workload is behind a TLS terminating load balancer or proxy, a client workload cannot be authenticated directly by the server via mTLS and X.509-SVID. So, an alternative is to forego authenticating the client at the load balancer or proxy and instead require that clients authenticate via SPIFFE JWT-SVIDs conveyed directly to the server via the application layer.

The scenario used in this example goes like this:
1. The server:
   - Creates a workloadapi_X509Source struct.
   - Creates a workloadapi_JWTSource struct.
   - Starts listening for HTTP requests over TLS. Only one resource is served at `/`.
2. The reverse proxy:
   - Starts listening for HTTP requests over TLS. It forwards requests to `/` only. 
3. The client:
   - Creates a workloadapi_X509Source struct.
   - Creates a workloadapi_JWTSource struct.
   - Fetches a JWT-SVID using the workloadapi_JWTSource.
   - Creates a `GET /` request with the JWT-SVID set as the value of the `Authorization` header.
   - Sends the request to the proxy using TLS authentication for establishing the connection. 
4. The proxy receives the request and forwards the request to the server.
5. The server receives the request, extracts the JWT-SVID from the `Authorization` header, and verifies the token. If the token is valid, it logs `Request received` and returns a response with a body containing the string `Success!`, otherwise an `NOT` HTTP code is returned.
6.  The proxy receives the response from the server and passes it to the client.
7.  The client receives the response. If the response has an HTTP 200 status, its body is logged, otherwise the HTTP status code is logged.

The **HTTP server** creates a [workloadapi_X509Source].

```C++
    err_t err;
    workloadapi_X509Source *x509source = workloadapi_NewX509Source(NULL, &err);
```

The socket path is provided as a client option. If the socket path is not provided, the value from the `SPIFFE_ENDPOINT_SOCKET` environment variable is used.

```C++
    err_t err;
    workloadapi_X509Source *x509source = workloadapi_NewX509Source(NULL, &err);
```
```C++
    spiffeid_ID id = spiffeid_FromString("spiffe://example.org/client", &err);
    spiffetls_ListenMode *mode = spiffetls_MTLSServerWithSource(
        tlsconfig_AuthorizeID(id), x509source);
    spiffetls_listenConfig config
        = { .base_TLS_conf = NULL, .listener_fd = -1 };
    int sock_fd;

    SSL *conn = spiffetls_ListenWithMode(port, mode, &config, &sock_fd, &err);
```

The server creates a `workloadapi_JWTSource` to obtain up-to-date JWT bundles from the Workload API.

```C++
    workloadapi_JWTSource *jwtsource = workloadapi_NewJWTSource(NULL, &err);
```

A middleware is added to authenticate client JWT-SVIDs provided in the `Authorization` header.
This middleware validates the token using the [jwtsvid_ParseAndValidate](using bundles obtained from the workloadapi_JWTSource).

```C++
    err_t err;
    jwtsvid_SVID *svid
        = jwtsvid_ParseAndValidate(token, source, audience, &err);
```

The client fetches a JWT-SVID from the Workload API (via the workloadapi_JWTSource) and adds it as a bearer token in the `Authorization` header.
```C++
    string_t header_arg = string_new("Authorization: Bearer ");
    header_arg = string_push(header_arg, jwtsvid_SVID_Marshal(jwtsvid));
    struct curl_slist *list = curl_slist_append(list, header_arg);
    /* ... */
```

```C++
    CURL *curl = curl_easy_init();
    /* ... */
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    /* ... */
```

That is it! The C-spiffe library fetches and automatically renews the X.509 SVID for the server and validates the client JWT SVIDs using the Workload API.

As soon as the TLS connection is established, the client sends an HTTP request to the server and gets a response.

## Building
To build the client and server workloads:
```bash
cd build/examples/
make
```

## Running
This example assumes the following preconditions:
- There is a SPIRE Server and Agent up and running.
- There is a Unix workload attestor configured.
- The trust domain is `example.org`
- The agent SPIFFE ID is `spiffe://example.org/host`.

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
./spiffe_jwt_server
```

### 3. Start the reverse proxy
To install and use the [Tinyproxy](https://github.com/tinyproxy/tinyproxy), follow the instructions on the [README.md](https://github.com/tinyproxy/tinyproxy#readme) file.
```bash
tinyproxy -c proxy/reverse_proxy.conf
```

### 4. Run the client
```bash
./spiffe_jwt_client
```

The server should display a log `Request received` and client `Success!`

To demonstrate a failure, an alternate audience value can be used. The server is expecting its own SPIFFE ID as the audience value and will reject the token if it doesn't match.

```
./spiffe_jwt_client spiffe://example.org/some-other-server

HTTP/1.1 401 Unauthorized
```

When the token is rejected, the server log shows:

```
spiffetls_ListenWithMode() failed: error 6
```