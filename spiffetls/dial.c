#include "c-spiffe/spiffetls/dial.h"
#include "c-spiffe/spiffetls/mode.h"
#include "c-spiffe/spiffetls/option.h"
#include "c-spiffe/spiffetls/tlsconfig/config.h"
#include <sys/socket.h>
#include <unistd.h>

static int createSocket(in_addr_t addr, in_port_t port)
{
    struct sockaddr_in address = { .sin_family = AF_INET,
                                   .sin_addr.s_addr = htonl(addr),
                                   .sin_port = htons(port) };

    const int sockfd = socket(/*IPv4*/ AF_INET, /*TCP*/ SOCK_STREAM, /*IP*/ 0);
    if(sockfd < 0) {
        // could not create socket
        return -1;
    }

    const int connect_ret
        = connect(sockfd, (const struct sockaddr *) &address, sizeof address);
    if(connect_ret < 0) {
        // could not connect socket with given address and port
        return -1;
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
            source = workloadapi_NewX509Source(NULL, err);
            if(*err) {
                // could not create source
                *err = ERR_CREATE;
                goto error;
            }

            /**err = workloadapi_X509Source_Start(source);
            if(*err) {
                // could not start source
                *err = ERROR1;
                goto error;
            }*/
        }
        mode->source = source;
        mode->bundle = x509bundle_SourceFromSource(source);
        mode->svid = x509svid_SourceFromSource(source);
    }

    SSL_CTX *tls_config
        = config->base_TLS_conf ? config->base_TLS_conf : createTLSContext();
    if(!tls_config) {
        *err = ERR_NULL;
        goto error;
    }

    switch(mode->mode) {
    case TLS_CLIENT_MODE:
        tlsconfig_HookTLSClientConfig(tls_config, mode->bundle,
                                      mode->authorizer, NULL);
        break;
    case MTLS_CLIENT_MODE:
        tlsconfig_HookMTLSClientConfig(tls_config, mode->svid, mode->bundle,
                                       mode->authorizer, NULL);
        break;
    case MTLS_WEBCLIENT_MODE:
    default:
        // unknown mode
        *err = ERR_UNKNOWN_MODE;
        goto error;
    }

    const int sockfd
        = config->dialer_fd > 0 ? config->dialer_fd : createSocket(addr, port);
    if(sockfd < 0) {
        // could not create socket with given address and port
        *err = ERR_CREATE;
        goto error;
    }

    SSL *conn = SSL_new(tls_config);
    if(!conn) {
        *err = ERR_CONNECT;
        goto error;
    } else if(SSL_set_fd(conn, sockfd) != 1) {
        *err = ERR_SET;
        goto error;
    }

    SSL_set_connect_state(conn);
    if(SSL_connect(conn) != 1) {
        // could not build a SSL session
        SSL_shutdown(conn);
        SSL_free(conn);
        close(sockfd);
        *err = ERR_CONNECT;
        goto error;
    }
    // successful handshake
    return conn;

error:
    return NULL;
}
