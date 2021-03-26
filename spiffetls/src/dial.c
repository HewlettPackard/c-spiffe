#include "dial.h"
#include "mode.h"
#include "option.h"
#include <arpa/inet.h>

#include <sys/socket.h>

static int createSocket(in_addr_t addr, in_port_t port)
{
    struct sockaddr_in address = { .sin_family = AF_INET,
                                   .sin_addr.s_addr = htonl(addr),
                                   .sin_port = htons(port) };
    memset(&address.sin_zero, 0, sizeof address.sin_zero);

    const int sockfd = socket(/*IPv4*/ AF_INET, /*TCP*/ SOCK_STREAM, /*IP*/ 0);
    if(connect(sockfd, (const struct sockaddr *) &address, sizeof address) < 0
       || sockfd < 0) {
        // could not create socket
        /// TODO: handle error
    }

    return sockfd;
}

static SSL_CTX *createTLSContext()
{
    const SSL_METHOD *method = TLS_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    return ctx;
}

SSL *spiffetls_DialWithMode(in_port_t port, in_addr_t addr,
                            spiffetls_DialMode *mode,
                            spiffetls_dialConfig *config, err_t *err)
{
    if(!mode->unneeded_source) {
        workloadapi_X509Source *source = mode->source;
        if(!source) {
            /// TODO: create source config
            source = workloadapi_NewX509Source(NULL, &err);

            if(*err) {
                /// TODO: handle source creation error
            }
        }

        mode->bundle = x509bundle_SourceFromSource(source);
        mode->svid = x509svid_SourceFromSource(source);
    }

    SSL_CTX *tls_config
        = config->base_TLS_conf ? config->base_TLS_conf : createTLSContext();

    switch(mode->mode) {
    case TLS_CLIENT_MODE:
        /// TODO: set config
        // HookTLSClientConfig
        break;
    case MTLS_CLIENT_MODE:
        /// TODO: set config
        // HookMTLSClientConfig
        break;
    case MTLS_WEBCLIENT_MODE:
        /// TODO: set config
        // HookMTLSWebClientConfig
        break;
    default:
        // unknown mode
        *err = ERROR1;
        goto error;
    }

    SSL *conn = SSL_new(tls_config);

    const int sockfd
        = config->dialer_fd > 0 ? config->dialer_fd : createSocket(addr, port);

    SSL_set_fd(conn, sockfd);
    SSL_set_connect_state(conn);
    if(SSL_connect(conn) != 1) {
        // could not build a SSL session
        *err = ERROR2;
        goto error;
    }

    // successful handshake
    return conn;

error:
    return NULL;
}
