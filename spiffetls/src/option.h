#ifndef INCLUDE_SPIFFETLS_OPTION_H
#define INCLUDE_SPIFFETLS_OPTION_H

#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    SSL_CTX *base_TLS_conf;
    int dialer_fd;
} spiffetls_dialConfig;

typedef struct {
    SSL_CTX *base_TLS_conf;
    int listener_fd;
} spiffetls_listenConfig;

typedef void (*spiffetls_DialOption)(spiffetls_dialConfig *);

void spiffetls_DialOption_apply(spiffetls_DialOption option,
                                spiffetls_dialConfig *config);

#ifdef __cplusplus
}
#endif

#endif // INCLUDE_SPIFFETLS_MODE_H
