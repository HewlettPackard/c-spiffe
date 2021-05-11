#include "spiffetls/src/listen.h"
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
    x509svid_SVID *svid
        = x509svid_Load("server_cert.pem", "server_key.pem", &err);

    if(svid == NULL || err != NO_ERROR) {
        printf("Could not load svid!\n");
        exit(-1);
    }

    x509svid_Source *svid_src = x509svid_SourceFromSVID(svid);
    spiffetls_ListenMode *mode = spiffetls_TLSServerWithRawConfig(svid_src);
    spiffetls_listenConfig config
        = { .base_TLS_conf = NULL, .listener_fd = 0 };

    int sock_fd;
    SSL *conn = spiffetls_ListenWithMode((in_port_t) 4433, mode, &config,
                                         &sock_fd, &err);

    if(conn == NULL) {
        printf("spiffetls_ListenWithMode() failed\n");
        exit(-1);
    }

    if(err != NO_ERROR) {
        printf("could not create TLS connection!");
        exit(-1);
    }

    x509svid_Source_Free(svid_src);
    spiffetls_ListenMode_Free(mode);

    const int fd = SSL_get_fd(conn);
    SSL_shutdown(conn);
    SSL_free(conn);
    close(fd);
    close(sock_fd);

    return 0;
}
