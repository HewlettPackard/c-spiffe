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
    printf("info: %s:%d: \n", __FILE__, __LINE__);
    if (sockfd < 0) {
        printf("ERROR opening socket");
        return -1;
    }
    printf("info: %s:%d: \n", __FILE__, __LINE__);
    if (connect(sockfd, (const struct sockaddr *) &address, sizeof(address)) < 0) {
        printf("ERROR connecting");
        return -1;
    }

    return sockfd;
}

static SSL_CTX *createTLSContext()
{
    const SSL_METHOD *method = TLS_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    printf("info: %s:%d: \n", __FILE__, __LINE__);
    if (!ctx)
    {
        printf("Unable to create SSL context");
        return NULL;
    }

    return ctx;
}

SSL *spiffetls_DialWithMode(in_port_t port, in_addr_t addr,
                            spiffetls_DialMode *mode,
                            spiffetls_dialConfig *config, err_t *err)
{
    printf("info: %s:%d: \n", __FILE__, __LINE__);
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
    printf("info: %s:%d: \n", __FILE__, __LINE__);
    switch(mode->mode) {
    case TLS_CLIENT_MODE:
        printf("info: %s:%d: \n", __FILE__, __LINE__);
        tlsconfig_HookTLSClientConfig(tls_config, mode->bundle,
                                      mode->authorizer, NULL);
        break;
    case MTLS_CLIENT_MODE:
        printf("info: %s:%d: \n", __FILE__, __LINE__);
        tlsconfig_HookMTLSClientConfig(tls_config, mode->svid, mode->bundle,
                                       mode->authorizer, NULL);
        break;
    case MTLS_WEBCLIENT_MODE:
    default:
        // unknown mode
        printf("info: %s:%d: \n", __FILE__, __LINE__);
        *err = ERROR1;
        goto error;
    }
    printf("info: %s:%d: \n", __FILE__, __LINE__);
    const int sockfd
        = config->dialer_fd > 0 ? config->dialer_fd : createSocket(addr, port);

    if(sockfd < 0) {
        printf("info: %s:%d: \n", __FILE__, __LINE__);
        // could not create socket with given address and port
        *err = ERROR1;
        goto error;
    }
    printf("info: %s:%d: \n", __FILE__, __LINE__);
    SSL *conn = SSL_new(tls_config);
    printf("info: %s:%d: - Conn: %p\n", __FILE__, __LINE__, conn);

    if (!conn)
    {
        printf("SSL_new() failed\n");
        goto error;
    }
    printf("info: %s:%d: - Conn: %p\n", __FILE__, __LINE__, conn);

    if (SSL_set_fd(conn, sockfd) != 1)
    {
        printf("Failed to SSL_set_fd\n");
        goto error;
    }
    printf("info: %s:%d: \n", __FILE__, __LINE__);

    printf("info: %s:%d: - Conn: %p\n", __FILE__, __LINE__, conn);

    SSL_set_fd(conn, sockfd);

    printf("info: %s:%d: - Conn: %p\n", __FILE__, __LINE__, conn);

    SSL_set_connect_state(conn);

    printf("info: %s:%d: - Conn: %p\n", __FILE__, __LINE__, conn);

    if(SSL_connect(conn) != 1) {
        // could not build a SSL session
        printf("info: %s:%d: \n", __FILE__, __LINE__);
        SSL_shutdown(conn);
        printf("info: %s:%d: \n", __FILE__, __LINE__);
        SSL_free(conn);
        printf("info: %s:%d: \n", __FILE__, __LINE__);
        close(sockfd);
        printf("info: %s:%d: \n", __FILE__, __LINE__);
        *err = ERROR3;
        goto error;
    }

    printf("info: %s:%d: - Conn: %p\n", __FILE__, __LINE__, conn);

    printf("info: %s:%d: \n", __FILE__, __LINE__);

    printf("Connected with %s encryption\n", SSL_get_cipher(conn));

     // successful handshake
    return conn;

error:
    return NULL;
}
