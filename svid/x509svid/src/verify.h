#ifndef INCLUDE_SVID_X509SVID_VERIFY_H
#define INCLUDE_SVID_X509SVID_VERIFY_H

#include "../../../bundle/x509bundle/src/source.h"
#include "../../../spiffeid/src/id.h"
#include "../../../utils/src/util.h"
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
 * as stb arrays. \param bundles [in] Source of bundles. \param id [out]
 * SPIFFE ID of the leaf certificate. \param err [out] Variable to get
 * information in the event of error. \returns stb array of possible chains
 * as stb arrays of X.509 certificate object pointers.
 */
X509 ***x509svid_ParseAndVerify(byte **raw_certs, x509bundle_Source *bundles,
                                spiffeid_ID *id, err_t *err);

/**
 * Verifies an X509-SVID chain using the X.509 bundle source. It returns
 * the SPIFFE ID of the X509-SVID and one or more chains back to a root in
 * the bundle.
 *
 * \param raw_certs [in] stb array of raw DER format of X.509 certificates
 * as stb arrays. \param bundles [in] Source of bundles. \param id [out]
 * SPIFFE ID of the leaf certificate. \param err [out] Variable to get
 * information in the event of error. \returns stb array of possible chains
 * as stb arrays of X.509 certificate object pointers.
 */
X509 ***x509svid_Verify(X509 **certs, x509bundle_Source *b, spiffeid_ID *id,
                        err_t *err);

/**
 * Extracts the SPIFFE ID from the URI SAN of the provided certificate. It
 * will return an an error if the certificate does not have exactly one URI
 * SAN with a well-formed SPIFFE ID.
 *
 * \param cert [in] X.509 certificate object pointer.
 * \param err [out] Variable to get information in the event of error.
 * \returns SPIFFE ID of the leaf certificate.
 */
spiffeid_ID x509svid_IDFromCert(X509 *cert, err_t *err);

#ifdef __cplusplus
}
#endif

#endif
