#ifndef INCLUDE_SVID_X509SVID_VERIFY_H
#define INCLUDE_SVID_X509SVID_VERIFY_H

#include "bundle/x509bundle/src/source.h"
#include "spiffeid/id.h"
#include "utils/src/util.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Verifies a certificate store using the X.509 bundle source. It returns
 * the SPIFFE ID of the leaf certificate.
 *
 * \param store_ctx [in] X.509 certificate store.
 * \param source [in] Source of bundles.
 * \param id [out] SPIFFE ID of the leaf certificate.
 * \returns true if the verification is successful, false otherwise.
 */
bool x509svid_Verify_cb(X509_STORE_CTX *store_ctx, x509bundle_Source *source,
                        spiffeid_ID *id);

#ifdef __cplusplus
}
#endif

#endif
