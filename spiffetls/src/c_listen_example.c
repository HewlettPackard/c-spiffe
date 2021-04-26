#include "spiffetls/src/dial.h"
#include <unistd.h>

int main(void)
{
    err_t err;
    x509svid_SVID *svid
        = x509svid_Load("server_cert.pem", "server_key.pem", &err);

    if(err != NO_ERROR) {
        printf("Could not load svid!\n");
        exit(-1);
    }

    x509svid_Source *svid_src = x509svid_SourceFromSVID(svid);
    spiffetls_ListenMode *mode = spiffetls_TLSServerWithRawConfig(svid_src);
    spiffetls_listenConfig config
        = { .base_TLS_conf = NULL, .listener_fd = 0 };

    SSL *conn = spiffetls_ListenWithMode((in_port_t) 4433,
                                         /*127.0.0.1*/ (in_addr_t) 0x7F000001,
                                         mode, &config, &err);

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

    return 0;
}