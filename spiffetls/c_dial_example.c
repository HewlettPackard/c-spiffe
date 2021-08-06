#include "c-spiffe/spiffetls/dial.h"
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

int main(int argc, char **argv)
{
    if(argc < 2) {
        printf("Too few arguments!\nUsage:\n\t./c_dial 'message'\n");
        exit(-1);
    }

    string_t message = string_new(argv[1]);
    message = string_push(message, "\n");
    // default address
    in_addr_t addr = /*127.0.0.1*/ 0x7F000001U;
    if(argc >= 3) {
        // get IP
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
    // default port
    in_port_t port = 4433U;
    if(argc >= 4) {
        in_port_t new_port;
        const int ret = sscanf(argv[3], "%hd", &new_port);

        if(ret == 1) {
            port = new_port;
        }
    }
    // default trust domain
    spiffeid_TrustDomain td = { string_new("example.org") };
    if(argc >= 5) {
        err_t err;
        spiffeid_TrustDomain new_td
            = spiffeid_TrustDomainFromString(argv[4], &err);

        if(!err) {
            spiffeid_TrustDomain_Free(&td);
            td = new_td;
        }
    }

    init_openssl();

    err_t err;
    workloadapi_X509Source *x509source = workloadapi_NewX509Source(NULL, &err);
    if(err != NO_ERROR) {
        printf("workloadapi_NewX509Source() failed\n");
        printf("err: %u\n", err);
        exit(-1);
    }

    err = workloadapi_X509Source_Start(x509source);
    if(err != NO_ERROR) {
        printf("workloadapi_X509Source_Start() failed\n");
        printf("err: %u\n", err);
        exit(-1);
    }

    tlsconfig_Authorizer *authorizer = tlsconfig_AuthorizeMemberOf(td);
    spiffetls_DialMode *mode
        = spiffetls_MTLSClientWithSource(authorizer, x509source);
    spiffetls_dialConfig config = { .base_TLS_conf = NULL, .dialer_fd = -1 };
    SSL *conn = spiffetls_DialWithMode(port, addr, mode, &config, &err);
    if(conn == NULL || err != NO_ERROR) {
        printf("spiffetls_DialWithMode() failed\n");
        printf("could not create TLS connection\n");
        printf("err: %u\n", err);
        exit(-1);
    }

    const int write = SSL_write(conn, message, strlen(message));
    if(write >= 0) {
        printf("Write value: %d\n", write);
        printf("Message sent: %s\n", message);
    } else {
        ERR_load_CRYPTO_strings();
        SSL_load_error_strings();
        printf("SSL error: %d\n", SSL_get_error(conn, write));
    }
    arrfree(message);

    /* get reply & decrypt */
    char buff[1024];
    const int bytes = SSL_read(conn, buff, sizeof(buff));
    buff[bytes] = 0;
    printf("Server replied: \"%s\"", buff);

    spiffeid_TrustDomain_Free(&td);
    spiffetls_DialMode_Free(mode);
    const int fd = SSL_get_fd(conn);
    SSL_shutdown(conn);
    SSL_free(conn);
    close(fd);

    return 0;
}
