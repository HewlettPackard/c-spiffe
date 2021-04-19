#include "spiffetls/src/dial.h"
#include <unistd.h>

int main(int argc, char **argv)
{


    err_t err;
    workloadapi_Client *client = workloadapi_NewClient(&err);
    const buffer_length = 14 * 1024;
    char buffer[buffer_length];
    char *message;
    if(argc < 2) {
        message = NULL;
    } else {
        message = argv[1];
    }

    
   

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


    const write = SSL_write(conn, message, strlen(message));

    printf("Write value: %d\n", write);
    if (write < 0)
    {
       
        ERR_load_CRYPTO_strings();
        SSL_load_error_strings();
        printf("Error: %d\n", SSL_get_error(conn, write));
    }
    SSL_read(conn, buffer, buffer_length);
    printf("reply from server: %s", buffer);

    err = workloadapi_Client_Close(client);
    if(err != NO_ERROR) {
        printf("close error! %d\n", (int) err);
    }
    workloadapi_Client_Free(client);
    if(err != NO_ERROR) {
        printf("client free error! %d\n", (int) err);
    }

    x509bundle_Source_Free(bundle_src);
    tlsconfig_Authorizer_Free(authorizer);
    spiffetls_DialMode_Free(mode);

    const int fd = SSL_get_fd(conn);
    SSL_shutdown(conn);
    SSL_free(conn);
    close(fd);

    return 0;
}