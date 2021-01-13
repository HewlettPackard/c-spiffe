#ifndef __INCLUDE_INTERNAL_X509UTIL_UTIL_H__
#define __INCLUDE_INTERNAL_X509UTIL_UTIL_H__

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "certpool.h"
#include "../../../utils/src/util.h"

X509** x509util_CopyX509Authorities(X509 **certs);
bool x509util_CertsEqual(X509 **certs1, X509 **certs2);
byte** x509util_RawCertsFromCerts(const X509 **certs);
byte* x509util_ConcatRawCertsFromCerts(const X509 **certs);
x509util_CertPool* x509util_NewCertPool(X509 **certs);

#endif