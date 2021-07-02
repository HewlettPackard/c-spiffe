#include "c-spiffe/spiffetls/listen.h"
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
    // default port
    in_port_t port = 4433U;
    if(argc >= 2) {
        in_port_t new_port;
        const int ret = sscanf(argv[1], "%hd", &new_port);

        if(ret == 1) {
            port = new_port;
        }
    }
    // default trust domain
    spiffeid_TrustDomain td = { string_new("example.org") };
    if(argc >= 3) {
        err_t err;
        spiffeid_TrustDomain new_td
            = spiffeid_TrustDomainFromString(argv[2], &err);

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
    spiffetls_ListenMode *mode
        = spiffetls_MTLSServerWithSource(authorizer, x509source);
    spiffetls_listenConfig config
        = { .base_TLS_conf = NULL, .listener_fd = 0 };

    while(true) {
        int sock_fd;
        SSL *conn = spiffetls_ListenWithMode(port, mode, &config, &sock_fd, &err);

        if(conn == NULL) {
            printf("spiffetls_ListenWithMode() failed\n");
            exit(-1);
        }
        if(err != NO_ERROR) {
            printf("could not create TLS connection!");
            exit(-1);
        }

        char buff[1024];
        const int bytes = SSL_read(conn, buff, sizeof(buff));
        buff[bytes] = 0;
        printf("Server received: %s\n", buff);

        SSL_write(conn, buff, strlen(buff));
        printf("Server replied: %s\n", buff);

        const int fd = SSL_get_fd(conn);
        SSL_shutdown(conn);
        SSL_free(conn);
        close(fd);
        close(sock_fd);
    }

    spiffeid_TrustDomain_Free(&td);
    spiffetls_ListenMode_Free(mode);

    return 0;
}
