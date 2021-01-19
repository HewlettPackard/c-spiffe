#ifndef __INCLUDE_INTERNAL_X509UTIL_UTIL_H__
#define __INCLUDE_INTERNAL_X509UTIL_UTIL_H__

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "certpool.h"
#include "../../../utils/src/util.h"

#ifdef __cplusplus
extern "C" {
#endif

X509** x509util_CopyX509Authorities(X509 **certs);
bool x509util_CertsEqual(X509 **certs1, X509 **certs2);
X509** x509util_ParseCertificates(const byte *bytes, const size_t len, err_t *err);
EVP_PKEY* x509util_ParsePrivateKey(const byte *bytes, const size_t len, err_t *err);
x509util_CertPool* x509util_NewCertPool(X509 **certs);

#ifdef __cplusplus
}
#endif

#endif