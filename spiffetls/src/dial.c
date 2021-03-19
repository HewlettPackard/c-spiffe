#include "dial.h"
#include "mode.h"
#include "option.h"
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <sys/socket.h>

int spiffetls_DialWithMode(SSL_CTX *ctx, in_port_t port, in_addr_t addr,
                           spiffetls_DialMode *mode,
                           spiffetls_DialOption *options, err_t *err)
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

    spiffetls_dialConfig opt = { NULL, 0 };
    for(size_t i = 0, size = arrlenu(options); i < size; ++i) {
        spiffetls_DialOption_apply(options[i], &opt);
    }

    SSL *tls_config = opt.base_TLS_conf ? opt.base_TLS_conf : NULL;
    if(tls_config)
        SSL_up_ref(tls_config);

    switch(mode->mode) {
    case TLS_CLIENT_MODE:
        /// TODO: set config
        break;
    case MTLS_CLIENT_MODE:
        /// TODO: set config
        break;
    case MTLS_WEBCLIENT_MODE:
        /// TODO: set config
        break;
    default:
        *err = ERROR1;
        goto error;
    }

    if(opt.dialer_fd) {
        /// TODO: dial with dialer
    } else {
        /// TODO: just dial
    }

    const struct sockaddr_in address
        = { .sin_family = AF_INET, .sin_addr.s_addr = addr, .sin_port = port };
    const int sockfd = socket(/*IPv4*/ AF_INET, /*TCP*/ SOCK_STREAM, /*IP*/ 0);
    if(bind(sockfd, (const struct sockaddr *) &address, sizeof address) < 0) {
        // could not bind socket to address
        *err = ERROR3;
        goto error;
    }

    return sockfd;

error:
    return 0;
}