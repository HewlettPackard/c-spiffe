#include "spiffetls/src/dial.h"
#include "spiffetls/src/mode.h"
#include "spiffetls/src/option.h"
#include "spiffetls/tlsconfig/src/config.h"
#include <unistd.h>

static int createSocket(in_addr_t addr, in_port_t port)
{
    struct sockaddr_in address = { .sin_family = AF_INET,
                                   .sin_addr.s_addr = htonl(addr),
                                   .sin_port = htons(port) };

    const int sockfd = socket(/*IPv4*/ AF_INET, /*TCP*/ SOCK_STREAM, /*IP*/ 0);
    if (sockfd < 0) {
        printf("ERROR opening socket\n");
        return -1;
    }
    if (connect(sockfd, (const struct sockaddr *) &address, sizeof(address)) < 0) {
        printf("ERROR connecting\n");
        return -1;
    }

    return sockfd;
}

static SSL_CTX *createTLSContext()
{
    const SSL_METHOD *method = TLS_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        printf("Unable to create SSL context\n");
        return NULL;
    }

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
                goto error;
            }
        }
        mode->source = source;
        mode->bundle = x509bundle_SourceFromSource(source);
        mode->svid = x509svid_SourceFromSource(source);
    }

    SSL_CTX *tls_config
        = config->base_TLS_conf ? config->base_TLS_conf : createTLSContext();

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
        *err = ERROR1;
        goto error;
    }
    const int sockfd
        = config->dialer_fd > 0 ? config->dialer_fd : createSocket(addr, port);

    if(sockfd < 0) {
        printf("could not create socket with given address and port\n");
        *err = ERROR1;
        goto error;
    }
    SSL *conn = SSL_new(tls_config);

    if (!conn)
    {
        printf("SSL_new() failed\n");
        goto error;
    }

    if (SSL_set_fd(conn, sockfd) != 1)
    {
        printf("Failed to SSL_set_fd\n");
        goto error;
    }

    SSL_set_fd(conn, sockfd);
    SSL_set_connect_state(conn);

    if(SSL_connect(conn) != 1) {
        printf("could not build a SSL session\n");
        SSL_shutdown(conn);
        SSL_free(conn);
        close(sockfd);
        *err = ERROR2;
        goto error;
    }
    // successful handshake
    return conn;

error:
    return NULL;
}
