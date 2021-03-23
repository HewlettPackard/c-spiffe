#ifndef INCLUDE_SPIFFETLS_OPTION_H
#define INCLUDE_SPIFFETLS_OPTION_H

#include <openssl/ssl.h>
// baseTLSConf *tls.Config
// dialer      *net.Dialer
// tlsoptions  []tlsconfig.Option

typedef struct {
    SSL_CTX *base_TLS_conf;
    int dialer_fd;
    // SSL_CTX *TLS_options;
} spiffetls_dialConfig;

typedef void (*spiffetls_DialOption)(spiffetls_dialConfig *);

void spiffetls_DialOption_apply(spiffetls_DialOption option,
                                spiffetls_dialConfig *config);

#endif // INCLUDE_SPIFFETLS_MODE_H