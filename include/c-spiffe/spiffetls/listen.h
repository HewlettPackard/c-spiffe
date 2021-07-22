#ifndef INCLUDE_SPIFFETLS_LISTEN_H
#define INCLUDE_SPIFFETLS_LISTEN_H

#include "c-spiffe/spiffetls/mode.h"
#include "c-spiffe/spiffetls/option.h"
#include <arpa/inet.h>
#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Establishes a TLS server with given port, address, mode and
 * configuration. If successful, returns a pointer to a established TLS
 * server object.
 *
 * \param port [in] Port number.
 * \param mode [in] Connection mode.
 * \param config [in] Connection configuration.
 * \param sock [out] Server socket fd.
 * \param err [out] Variable to get information in the event of error.
 * \returns Connected server TLS object pointer if successful, NULL otherwise.
 */
SSL *spiffetls_ListenWithMode(in_port_t port, spiffetls_ListenMode *mode,
                              spiffetls_listenConfig *config, int *sock,
                              err_t *err);

/**
 * Establishes a TLS server with given port, address, mode and
 * configuration. If successful, returns a pointer to a established TLS
 * server object.
 *
 * \param port [in] Port number.
 * \param mode [in] Connection mode.
 * \param config [in] Connection configuration.
 * \param sock [out] Server socket fd.
 * \param control_sock [in] socket fd for signaling exit.
 * \param timeout [in] timeout used internally with poll().
 * \param err [out] Variable to get information in the event of error.
 * \returns Connected server TLS object pointer if successful, NULL otherwise.
 */                  

SSL *spiffetls_PollWithMode(in_port_t port, spiffetls_ListenMode *mode,
                            spiffetls_listenConfig *config, int *sock,
                            int control_sock, int timeout,
                            err_t *err);
#ifdef __cplusplus
}
#endif

#endif // INCLUDE_SPIFFETLS_DIAL_H
