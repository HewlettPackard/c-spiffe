#ifndef __INCLUDE_BUNDLE_X509BUNDLE_SET_H__
#define __INCLUDE_BUNDLE_X509BUNDLE_SET_H__

#include <stdlib.h>
#include "bundle.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct map_string_x509bundle_Bundle
{
    string_t key;
    x509bundle_Bundle *value;
} map_string_x509bundle_Bundle;

typedef struct x509bundle_Set
{
    //map of bundles
    map_string_x509bundle_Bundle *bundles;
    //lock
    mtx_t mtx;
} x509bundle_Set;

x509bundle_Set* x509bundle_NewSet(const int n_args, ...);

void x509bundle_Set_Add(x509bundle_Set *s, x509bundle_Bundle *bundle);
void x509bundle_Set_Remove(x509bundle_Set *s, const spiffeid_TrustDomain *td);
bool x509bundle_Set_Has(x509bundle_Set *s, const spiffeid_TrustDomain *td);
x509bundle_Bundle* x509bundle_Set_Get(x509bundle_Set *s, 
                                    const spiffeid_TrustDomain *td, 
                                    bool *suc);
x509bundle_Bundle** x509bundle_Set_Bundles(x509bundle_Set *s);
uint32_t x509bundle_Set_Len(x509bundle_Set *s);
x509bundle_Bundle* x509bundle_Set_GetX509BundleForTrustDomain(
                                    x509bundle_Set *s, 
                                    const spiffeid_TrustDomain *td, 
                                    err_t *err);
void x509bundle_Set_Free(x509bundle_Set *s);

#ifdef __cplusplus
}
#endif

#endif