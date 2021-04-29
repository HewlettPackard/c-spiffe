#include "spiffetls/src/dial.h"
#include <unistd.h>

int main(void)
{
    err_t err;
    workloadapi_Client *client = workloadapi_NewClient(&err);

    if(err != NO_ERROR) {
        printf("client error! %d\n", (int) err);
        exit(-1);
    }

    workloadapi_Client_defaultOptions(client, NULL);
    err = workloadapi_Client_Connect(client);
    if(err != NO_ERROR) {
        printf("conn error! %d\n", (int) err);
        exit(-1);
    }

    x509bundle_Set *set = workloadapi_Client_FetchX509Bundles(client, &err);

    if(err != NO_ERROR) {
        printf("fetch error! %d\n", (int) err);
        exit(-1);
    }

    x509bundle_Source *bundle_src = x509bundle_SourceFromSet(set);

    spiffeid_TrustDomain td = { "example.org" };
    tlsconfig_Authorizer *authorizer = tlsconfig_AuthorizeMemberOf(td);

    spiffetls_DialMode *mode
        = spiffetls_TLSClientWithRawConfig(authorizer, bundle_src);
    spiffetls_dialConfig config = { .base_TLS_conf = NULL, .dialer_fd = 0 };

    SSL *conn = spiffetls_DialWithMode((in_port_t) 4433,
                                       /*127.0.0.1*/ (in_addr_t) 0x7F000001,
                                       mode, &config, &err);

    if(err != NO_ERROR) {
        printf("could not create TLS connection!");
        exit(-1);
    }

    err = workloadapi_Client_Close(client);
    if(err != NO_ERROR) {
        printf("close error! %d\n", (int) err);
    }
    workloadapi_Client_Free(client);
    if(err != NO_ERROR) {
        printf("client free error! %d\n", (int) err);
    }

    spiffetls_DialMode_Free(mode);

    const int fd = SSL_get_fd(conn);
    SSL_shutdown(conn);
    SSL_free(conn);
    close(fd);

    return 0;
}