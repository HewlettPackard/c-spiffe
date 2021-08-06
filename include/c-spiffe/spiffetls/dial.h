#ifndef INCLUDE_SPIFFETLS_DIAL_H
#define INCLUDE_SPIFFETLS_DIAL_H

#include "c-spiffe/spiffetls/mode.h"
#include "c-spiffe/spiffetls/option.h"
#include <arpa/inet.h>
#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Establishes a TLS connection with given port, address, mode and
 * configuration. If successful, returns a pointer to a established TLS
 * connection object.
 *
 * \param port [in] Port number.
 * \param addr [in] Address code.
 * \param mode [in] Connection mode.
 * \param config [in] Connection configuration.
 * \param err [out] Variable to get information in the event of error.
 * \returns Connected TLS object pointer if successful, NULL otherwise.
 */
SSL *spiffetls_DialWithMode(in_port_t port, in_addr_t addr,
                            spiffetls_DialMode *mode,
                            spiffetls_dialConfig *config, err_t *err);

#ifdef __cplusplus
}
#endif

#endif // INCLUDE_SPIFFETLS_DIAL_H
