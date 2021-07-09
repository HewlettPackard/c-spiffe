#ifndef INCLUDE_INTERNAL_X509UTIL_UTIL_H
#define INCLUDE_INTERNAL_X509UTIL_UTIL_H

#include "c-spiffe/internal/x509util/certpool.h"
#include "c-spiffe/utils/util.h"
#include <openssl/evp.h>
#include <openssl/x509.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Copies an array of X.509 certificate objects.
 *
 * \param certs [in] stb array of X.509 certificate object pointers.
 * \returns a stb array with a copy of the objects, with the reference
 * count increased. Must be freed iterations over the array using
 * X509_free and then arrfree.
 */
X509 **x509util_CopyX509Authorities(X509 **certs);

/**
 * Checks if two stb arrays of X.509 certificates are equal.
 *
 * \param certs1 [in] First stb array of X.509 certificate object pointers.
 * \param certs2 [in] First stb array of X.509 certificate object pointers.
 * \returns <tt>true</tt> if the items on the arrays are equal
 * element-wise, <tt>false</tt> otherwise.
 */
bool x509util_CertsEqual(X509 **certs1, X509 **certs2);

/**
 * Parse X.509 certificates in raw format.
 *
 * \param bytes [in] Array of raw bytes in DER format.
 * \param len [in] Length of the array.
 * \param err [out] Variable to get information in the event of error.
 * \returns stb array of X.509 certificate object pointers. Must be freed
 * iterations over the array using X509_free and then arrfree.
 */
X509 **x509util_ParseCertificates(const byte *bytes, const size_t len,
                                  err_t *err);

/**
 * Parse a private key in raw format.
 *
 * \param bytes [in] Array of raw bytes in DER format.
 * \param len [in] Length of the array.
 * \param err [out] Variable to get information in the event of error.
 * \returns Parsed private key object pointer. Must be freed using
 * EVP_PKEY_free.
 */
EVP_PKEY *x509util_ParsePrivateKey(const byte *bytes, const size_t len,
                                   err_t *err);

/**
 * New certificate pool.
 *
 * \param certs [in] stb array of X.509 certificate object pointers.
 * \returns Certificate pool object pointer. Must be freed using
 * x509util_CertPool_Free.
 */
x509util_CertPool *x509util_NewCertPool(X509 **certs);

#ifdef __cplusplus
}
#endif

#endif
