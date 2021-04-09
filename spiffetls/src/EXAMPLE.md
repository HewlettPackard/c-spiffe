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
### Compiling
Always compile with make.

Run example: 
``` bash
./c_dial
```