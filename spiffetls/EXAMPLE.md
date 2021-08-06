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


## SPIFFE TLS Listen

SPIFFE TLS Listen for C example.

### Load SVID
``` C++
err_t err;
x509svid_SVID *svid
    = x509svid_Load("server_cert.pem", "server_key.pem", &err);
```
### Parameters
``` C++
x509svid_Source *svid_src = x509svid_SourceFromSVID(svid);
spiffetls_ListenMode *mode = spiffetls_TLSServerWithRawConfig(svid_src);
spiffetls_listenConfig config
    = { .base_TLS_conf = NULL, .listener_fd = 0 };
```
Set up listen mode and empty configuration.
### Dial and create TLS connection
``` C++
int sockfd;
SSL *conn = spiffetls_ListenWithMode((in_port_t) 4433,
                                     /*127.0.0.1*/ (in_addr_t) 0x7F000001,
                                     mode, &config, &sockfd, &err);
```
Listen with port, address with the given mode and configuration. Get a connection object and server socket.
### Free
Don't forget to free allocated objects and close resources.
``` C++
x509svid_Source_Free(svid_src);
spiffetls_ListenMode_Free(mode);

const int fd = SSL_get_fd(conn);
SSL_shutdown(conn);
SSL_free(conn);
close(fd);
close(sock_fd);
```

## SPIFFE TLS Dial

SPIFFE TLS Dial for C example.
### Client object
``` C++
err_t err;
workloadapi_Client *client = workloadapi_NewClient(&err);
// ...
workloadapi_Client_defaultOptions(client, NULL);
// ...
x509bundle_Set *set = workloadapi_Client_FetchX509Bundles(client, &err);
```
Initialize client and fetch set of X.509 bundles.

### Parameters
``` C++
x509bundle_Source *bundle_src = x509bundle_SourceFromSet(set);

spiffeid_TrustDomain td = { "example.org" };
tlsconfig_Authorizer *authorizer = tlsconfig_AuthorizeMemberOf(td);

spiffetls_DialMode *mode
    = spiffetls_TLSClientWithRawConfig(authorizer, bundle_src);
spiffetls_dialConfig config = { .base_TLS_conf = NULL, .dialer_fd = 0 };

```
Set up dial mode and empty configuration.

### Dial and create TLS connection
``` C++
SSL *conn = spiffetls_DialWithMode((in_port_t) 4433,
                                    /*127.0.0.1*/ (in_addr_t) 0x7F000001,
                                    mode, &config, &err);
```
Dial with port, address with the given mode and configuration. Get a connection object.
### Free
Don't forget to free allocated objects and close resources.
``` C++
err = workloadapi_Client_Close(client);
// ...
workloadapi_Client_Free(client);
// ...
x509bundle_Source_Free(bundle_src);
tlsconfig_Authorizer_Free(authorizer);
spiffetls_DialMode_Free(mode);

const int fd = SSL_get_fd(conn);
SSL_shutdown(conn);
SSL_free(conn);
close(fd);
```
## Compiling
Always compile with make.

Run example: 
``` bash
./c_dial
./c_listen
```
