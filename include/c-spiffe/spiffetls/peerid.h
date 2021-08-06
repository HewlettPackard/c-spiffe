#ifndef INCLUDE_SPIFFETLS_PEERID_H
#define INCLUDE_SPIFFETLS_PEERID_H

#include "c-spiffe/spiffeid/id.h"
#include "c-spiffe/utils/util.h"
#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Gets peer spiffe ID from given TLS connection, if it exists.
 *
 * \param conn [in] TLS connection object pointer.
 * \param err [out] Variable to get information in the event of error.
 * \returns spiffe ID object of the given connection, if it exists. Empty
 * spiffe ID, otherwise.
 */
spiffeid_ID spiffetls_PeerIDFromConn(SSL *conn, err_t *err);

#ifdef __cplusplus
}
#endif

#endif // INCLUDE_SPIFFETLS_PEERID_H
