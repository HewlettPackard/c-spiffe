#include "spiffetls/src/dial.h"
#include <unistd.h>

void init_openssl()
{
    SSL_load_error_strings();
    SSL_library_init();
}

int main(int argc, char **argv)
{
    char buff[1024];
    int bytes;
    char *message = NULL;

    if(argc < 2) {
        printf("Too few arguments!\nUsage:\n\t./c_dial 'message'\n");
        exit(-1);
    }

    message = argv[1];

    init_openssl();
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

    if(conn == NULL) {
        printf("spiffetls_DialWithMode() failed\n");
        exit(-1);
    }

    if(err != NO_ERROR) {
        printf("could not create TLS connection\n");
        exit(-1);
    }

    int write = SSL_write(conn, message, sizeof(message));
    printf("Write value: %d\n", write);
    if (write < 0) {

        ERR_load_CRYPTO_strings();
        SSL_load_error_strings();
        printf("Error: %d\n", SSL_get_error(conn, write));
    }

    bytes = SSL_read(conn, buff, sizeof(buff)); /* get reply & decrypt */

    buff[bytes] = 0;
    printf("Received: \"%s\"\n", buff);

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
