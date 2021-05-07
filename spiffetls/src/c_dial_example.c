#include "spiffetls/src/dial.h"
#include <unistd.h>

/* returns 1 if little endian, 0 otherwise */
int is_little_endian(void)
{
    uint32_t x = 1;
    uint8_t c = *((uint8_t *) &x);
    return c;
}

void init_openssl()
{
    SSL_load_error_strings();
    SSL_library_init();
}

workloadapi_X509Context *fetch_context(void)
{
    err_t err;
    workloadapi_Client *client = workloadapi_NewClient(&err);
    if(err != NO_ERROR) {
        printf("Client error: %u\n", err);
        return NULL;
    }
    workloadapi_Client_defaultOptions(client, NULL);
    err = workloadapi_Client_Connect(client);
    if(err != NO_ERROR) {
        printf("Conn error: %u\n", err);
        return NULL;
    }

    workloadapi_X509Context *x509context
        = workloadapi_Client_FetchX509Context(client, &err);
    if(err != NO_ERROR) {
        printf("Could not fetch x509 context: %u\n", err);
        return NULL;
    }

    return x509context;
}

int main(int argc, char **argv)
{
    if(argc < 2) {
        printf("Too few arguments!\nUsage:\n\t./c_dial 'message'\n");
        exit(-1);
    }

    char *message = argv[1];
    in_addr_t addr = /*127.0.0.1*/ 0x7F000001U;
    if(argc >= 3) {
        uint8_t ip[4];
        const int dir[2][4] = { /*big endian*/ { 0, 1, 2, 3 },
                                /*little endian*/ { 3, 2, 1, 0 } };
        const int *my_dir = dir[is_little_endian()];
        const int ret = sscanf(argv[2], "%hhd.%hhd.%hhd.%hhd", ip + my_dir[0],
                               ip + my_dir[1], ip + my_dir[2], ip + my_dir[3]);
        if(ret == 4) {
            addr = *((in_addr_t *) ip);
        }
    }

    init_openssl();

    workloadapi_X509Context *x509context = fetch_context();
    if(x509context == NULL) {
        exit(-1);
    }

    spiffeid_TrustDomain td = { "example.org" };
    tlsconfig_Authorizer *authorizer = tlsconfig_AuthorizeMemberOf(td);
    spiffetls_DialMode *mode = spiffetls_MTLSClient(authorizer);
    spiffetls_dialConfig config = { .base_TLS_conf = NULL, .dialer_fd = -1 };
    err_t err;
    SSL *conn = spiffetls_DialWithMode(x509context, (in_port_t) 4433U, addr,
                                       mode, &config, &err);
    if(conn == NULL || err != NO_ERROR) {
        printf("spiffetls_DialWithMode() failed\n");
        printf("could not create TLS connection\n");
        printf("err: %u\n", err);
        exit(-1);
    }

    const int write = SSL_write(conn, message, strlen(message));
    if(write >= 0) {
        printf("Write value: %d\n", write);
        printf("Write content: %s\n", message);
    } else {
        ERR_load_CRYPTO_strings();
        SSL_load_error_strings();
        printf("Error: %d\n", SSL_get_error(conn, write));
    }

    /* get reply & decrypt */
    char buff[1024];
    const int bytes = SSL_read(conn, buff, sizeof(buff));
    buff[bytes] = 0;
    printf("Received: \"%s\"\n", buff);

    spiffetls_DialMode_Free(mode);
    const int fd = SSL_get_fd(conn);
    SSL_shutdown(conn);
    SSL_free(conn);
    close(fd);

    return 0;
}