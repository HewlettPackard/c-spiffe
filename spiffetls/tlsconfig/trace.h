#ifndef INCLUDE_SPIFFETLS_TLSCONFIG_TRACE_H
#define INCLUDE_SPIFFETLS_TLSCONFIG_TRACE_H

#include "utils/util.h"
#include <openssl/ssl.h>
#include <openssl/x509.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    X509 *cert;
    err_t err;
} tlsconfig_GotCertificateInfo;

typedef struct {

} tlsconfig_Trace;

void *tlsconfig_GetCertificate(tlsconfig_Trace *trace);
void tlsconfig_GotCertificate(tlsconfig_Trace *trace, const void *any,
                              const tlsconfig_GotCertificateInfo *info);

#ifdef __cplusplus
extern "C" {
#endif

#endif // INCLUDE_SPIFFETLS_TLSCONFIG_TRACE_H
