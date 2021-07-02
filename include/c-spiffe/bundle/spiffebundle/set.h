#ifndef INCLUDE_BUNDLE_SPIFFEBUNDLE_SET_H
#define INCLUDE_BUNDLE_SPIFFEBUNDLE_SET_H

#include "c-spiffe/bundle/spiffebundle/bundle.h"
#include "c-spiffe/utils/util.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef struct map_string_spiffebundle_Bundle {
    string_t key;
    spiffebundle_Bundle *value;
} map_string_spiffebundle_Bundle;

typedef struct spiffebundle_Set {
    mtx_t mtx;
    map_string_spiffebundle_Bundle *bundles;
} spiffebundle_Set;

spiffebundle_Set *spiffebundle_NewSet(int n_args, ...);
void spiffebundle_Set_Free(spiffebundle_Set* set);
void spiffebundle_Set_Add(spiffebundle_Set *s, spiffebundle_Bundle *bundle);
void spiffebundle_Set_Remove(spiffebundle_Set *s,
                             const spiffeid_TrustDomain td);
bool spiffebundle_Set_Has(spiffebundle_Set *s, const spiffeid_TrustDomain td);
spiffebundle_Bundle *spiffebundle_Set_Get(spiffebundle_Set *s,
                                          const spiffeid_TrustDomain td,
                                          bool *suc);
spiffebundle_Bundle **spiffebundle_Set_Bundles(spiffebundle_Set *s);
uint32_t spiffebundle_Set_Len(spiffebundle_Set *s);
spiffebundle_Bundle *spiffebundle_Set_GetBundleForTrustDomain(
    spiffebundle_Set *s, const spiffeid_TrustDomain td, err_t *err);
x509bundle_Bundle *spiffebundle_Set_GetX509BundleForTrustDomain(
    spiffebundle_Set *s, const spiffeid_TrustDomain td, err_t *err);
jwtbundle_Bundle *spiffebundle_Set_GetJWTBundleForTrustDomain(
    spiffebundle_Set *s, const spiffeid_TrustDomain td, err_t *err);
void spiffebundle_Set_Free(spiffebundle_Set *s);

#ifdef __cplusplus
}
#endif

#endif
