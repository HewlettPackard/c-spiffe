#include "c-spiffe/spiffeid/id.h"
#include "c-spiffe/spiffetls/dial.h"
#include "c-spiffe/spiffetls/mode.h"
#include "c-spiffe/spiffetls/option.h"
#include "c-spiffe/workload/x509source.h"
#include <unistd.h>

void init_openssl()
{
    SSL_load_error_strings();
    SSL_library_init();
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

    const in_port_t port = 55555U;
    const in_addr_t addr = /*127.0.0.1*/ 0x7F000001U; // localhost
    spiffeid_ID id = spiffeid_FromString("spiffe://example.org/server", &err);
    spiffetls_DialMode *mode = spiffetls_MTLSClientWithSource(
        tlsconfig_AuthorizeID(id), x509source);
    spiffetls_dialConfig config = { .base_TLS_conf = NULL, .dialer_fd = -1 };

    SSL *conn = spiffetls_DialWithMode(port, addr, mode, &config, &err);

    if(conn == NULL || err != NO_ERROR) {
        printf("spiffetls_DialWithMode() failed: error %u\n", err);
        exit(-1);
    }

    const char message[] = "Hello server";
    const int write = SSL_write(conn, message, strlen(message));
    if(write < 0) {
        ERR_load_CRYPTO_strings();
        SSL_load_error_strings();
        printf("SSL_write() failed: error %d\n", SSL_get_error(conn, write));
        exit(-1);
    }

    /* get reply & decrypt */
    char buff[1024];
    const int read = SSL_read(conn, buff, sizeof(buff));
    if(read >= 0) {
        buff[read] = 0;
        printf("Server replied: \"%s\"", buff);
    } else {
        ERR_load_CRYPTO_strings();
        SSL_load_error_strings();
        printf("SSL_read() failed: error %d\n", SSL_get_error(conn, read));
    }

    spiffeid_ID_Free(&id);
    spiffetls_DialMode_Free(mode);
    const int fd = SSL_get_fd(conn);
    SSL_shutdown(conn);
    SSL_free(conn);
    close(fd);

    return 0;
}
