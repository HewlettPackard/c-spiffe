#ifndef INCLUDE_SPIFFETLS_LISTEN_H
#define INCLUDE_SPIFFETLS_LISTEN_H

#include "spiffetls/src/mode.h"
#include "spiffetls/src/option.h"
#include "spiffetls/tlsconfig/src/authorizer.h"
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <sys/socket.h>

SSL *spiffetls_ListenWithMode(in_port_t port, in_addr_t addr,
                              spiffetls_ListenMode *mode,
                              spiffetls_listenConfig *config, err_t *err);

#endif // INCLUDE_SPIFFETLS_DIAL_H
