#include "c-spiffe/spiffeid/id.h"
#include "c-spiffe/spiffetls/listen.h"
#include "c-spiffe/spiffetls/mode.h"
#include "c-spiffe/spiffetls/option.h"
#include "c-spiffe/workload/x509source.h"
#include <unistd.h>

void init_openssl()
{
    SSL_load_error_strings();
    SSL_library_init();
}

void handleConnection(SSL *conn)
{
    char buff[1024];
    const int read = SSL_read(conn, buff, sizeof(buff));

    if(read < 0) {
        ERR_load_CRYPTO_strings();
        SSL_load_error_strings();
        printf("SSL_read() failed: error %d\n", SSL_get_error(conn, read));
        return;
    } else {
        buff[read] = 0;
        printf("Client says: %s\n", buff);
    }

    const char message[] = "Hello client";
    const int write = SSL_write(conn, message, strlen(message));
    if(write < 0) {
        ERR_load_CRYPTO_strings();
        SSL_load_error_strings();
        printf("SSL_write() failed: error %d\n", SSL_get_error(conn, write));
    }
}

int main(void)
{
    init_openssl();

    err_t err;
    workloadapi_X509Source *x509source = workloadapi_NewX509Source(NULL, &err);
    if(err != NO_ERROR) {
        printf("workloadapi_NewX509Source() failed: error %u\n", err);
        exit(-1);
    }

    err = workloadapi_X509Source_Start(x509source);
    if(err != NO_ERROR) {
        printf("workloadapi_X509Source_Start() failed: error %u\n", err);
        exit(-1);
    }

    // default port
    const in_port_t port = 55555U;
    spiffeid_ID id = spiffeid_FromString("spiffe://example.org/client", &err);
    spiffetls_ListenMode *mode = spiffetls_MTLSServerWithSource(
        tlsconfig_AuthorizeID(id), x509source);
    spiffetls_listenConfig config
        = { .base_TLS_conf = NULL, .listener_fd = -1 };
    int sock_fd;

    while(true) {
        SSL *conn
            = spiffetls_ListenWithMode(port, mode, &config, &sock_fd, &err);

        if(err != NO_ERROR) {
            printf("spiffetls_ListenWithMode() failed: error %u\n", err);
        } else {
            handleConnection(conn);
            const int fd = SSL_get_fd(conn);
            SSL_shutdown(conn);
            SSL_free(conn);
            close(fd);
            close(sock_fd);
        }
    }

    spiffeid_ID_Free(&id);
    spiffetls_ListenMode_Free(mode);

    return 0;
}
