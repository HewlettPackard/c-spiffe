#ifndef INCLUDE_SPIFFETLS_PEERID_H
#define INCLUDE_SPIFFETLS_PEERID_H

#include "spiffeid/src/id.h"
#include "svid/x509svid/src/verify.h"
#include "utils/src/util.h"
#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

spiffeid_ID spiffetls_PeerIDFromConn(SSL *conn, err_t *err);

#ifdef __cplusplus
}
#endif

#endif // INCLUDE_SPIFFETLS_PEERID_H
