#ifndef INCLUDE_SPIFFETLS_LISTEN_H
#define INCLUDE_SPIFFETLS_LISTEN_H

#include "spiffetls/src/mode.h"
#include "spiffetls/src/option.h"
#include "spiffetls/tlsconfig/src/authorizer.h"
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Establishes a TLS server with given port, address, mode and
 * configuration. If successful, returns a pointer to a established TLS
 * server object.
 * \param ctx [in] workloadapi x509 context object.
 * \param port [in] Port number.
 * \param mode [in] Connection mode.
 * \param config [in] Connection configuration.
 * \param sock [out] Server socket fd.
 * \param err [out] Variable to get information in the event of error.
 * \returns Connected server TLS object pointer if successful, NULL otherwise.
 */
SSL *spiffetls_ListenWithMode(workloadapi_X509Context *x509ctx, in_port_t port,
                              spiffetls_ListenMode *mode,
                              spiffetls_listenConfig *config, int *sock,
                              err_t *err);

#ifdef __cplusplus
}
#endif

#endif // INCLUDE_SPIFFETLS_DIAL_H
