#ifndef INCLUDE_SVID_X509SVID_VERIFY_H
#define INCLUDE_SVID_X509SVID_VERIFY_H

#include "bundle/x509bundle/src/source.h"
#include "spiffeid/src/id.h"
#include "utils/src/util.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Parses and verifies an X509-SVID chain using the X.509 bundle source. It
 * returns the SPIFFE ID of the X509-SVID and one or more chains back to a
 * root in the bundle.
 *
 * \param raw_certs [in] stb array of raw DER format of X.509 certificates
 * as stb arrays.
 * \param bundles [in] Source of bundles.
 * \param id [out] SPIFFE ID of the leaf certificate.
 * \param err [out] Variable to get information in the event of error.
 * \returns stb array of possible chains as stb arrays of X.509 certificate
 * object pointers.
 */
X509 ***x509svid_ParseAndVerify(byte **raw_certs, x509bundle_Source *bundles,
                                spiffeid_ID *id, err_t *err);

/**
 * Verifies an X509-SVID chain using the X.509 bundle source. It returns
 * the SPIFFE ID of the X509-SVID and one or more chains back to a root in
 * the bundle.
 *
 * \param certs [in] stb array of X.509 certificate pointers.
 * \param bundles [in] Source of bundles.
 * \param id [out] SPIFFE ID of the leaf certificate.
 * \param err [out] Variable to get information in the event of error.
 * \returns stb array of possible chains as stb arrays of X.509 certificate
 * object pointers.
 */
X509 ***x509svid_Verify(X509 **certs, x509bundle_Source *bundles,
                        spiffeid_ID *id, err_t *err);

/**
 * ...
 *
 *
 */
bool x509svid_Verify_cb(X509_STORE_CTX *store_ctx, x509bundle_Source *source,
                        spiffeid_ID *id);

#ifdef __cplusplus
}
#endif

#endif
