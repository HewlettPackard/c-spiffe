#ifndef __INCLUDE_INTERNAL_X509UTIL_CERTPOOL_H__
#define __INCLUDE_INTERNAL_X509UTIL_CERTPOOL_H__

#include <openssl/x509.h>
#include "../../../utils/src/util.h"
#include "../../../utils/src/stb_ds.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct map_string_int_arr
{
    string_t key;
    int *value;
} map_string_int_arr;

typedef struct x509util_CertPool
{
    X509 **certs;
    map_string_int_arr *subj_keyid_idcs;
    map_string_int_arr *name_idcs;
} x509util_CertPool;

x509util_CertPool* x509util_CertPool_New(void);
void x509util_CertPool_AddCert(x509util_CertPool *certpool, X509 *cert);
bool x509util_CertPool_contains(x509util_CertPool *certpool, X509 *cert);
int* x509util_CertPool_findPotentialParents(x509util_CertPool *certpool, 
                                            X509 *cert);
void x509util_CertPool_Free(x509util_CertPool *certpool);

#ifdef __cplusplus
}
#endif

#endif