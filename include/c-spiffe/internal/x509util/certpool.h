#ifndef INCLUDE_INTERNAL_X509UTIL_CERTPOOL_H
#define INCLUDE_INTERNAL_X509UTIL_CERTPOOL_H

#include "c-spiffe/utils/util.h"
#include <openssl/x509.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct map_string_int_arr {
    string_t key;
    int *value;
} map_string_int_arr;

/** Pool of X.509 certificates. */
typedef struct x509util_CertPool {
    X509 **certs;
    map_string_int_arr *subj_keyid_idcs;
    map_string_int_arr *name_idcs;
} x509util_CertPool;

/**
 * Creates a new empty pool certificate object.
 */
x509util_CertPool *x509util_CertPool_New(void);

/**
 * Adds a certificate to the pool.
 *
 * \param certpool [in] Certificate pool object pointer.
 * \param cert [in] X.509 certificate object pointer.
 */
void x509util_CertPool_AddCert(x509util_CertPool *certpool, X509 *cert);

/**
 * Checks if a pool contains a given certificate.
 *
 * \param certpool [in] Certificate pool object pointer.
 * \param cert [in] X.509 certificate object pointer.
 * \returns <tt>true</tt> if the pool contains the certificate,
 * <tt>false</tt> otherwise.
 */
bool x509util_CertPool_contains(x509util_CertPool *certpool, X509 *cert);

/**
 * Frees a certificate pool object.
 *
 * \param certpool [in] A certificate pool object pointer to be
 * deallocated.
 */
void x509util_CertPool_Free(x509util_CertPool *certpool);

#ifdef __cplusplus
}
#endif

#endif
