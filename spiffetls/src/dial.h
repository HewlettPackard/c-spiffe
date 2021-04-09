#ifndef INCLUDE_SPIFFETLS_DIAL_H
#define INCLUDE_SPIFFETLS_DIAL_H

#include "spiffetls/src/mode.h"
#include "spiffetls/src/option.h"
#include "spiffetls/tlsconfig/src/authorizer.h"
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <sys/socket.h>

SSL *spiffetls_DialWithMode(in_port_t port, in_addr_t addr,
                            spiffetls_DialMode *mode,
                            spiffetls_dialConfig *config, err_t *err);

#endif // INCLUDE_SPIFFETLS_DIAL_H
