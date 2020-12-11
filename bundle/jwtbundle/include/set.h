#ifndef __INCLUDE_BUNDLE_JWTBUNDLE_SET_H__
#define __INCLUDE_BUNDLE_JWTBUNDLE_SET_H__

//qsort algorithm
#include <stdlib.h>
#include "bundle.h"

typedef struct map_string_jwtbundle_Bundle
{
    string_t key;
    jwtbundle_Bundle *value;
} map_string_jwtbundle_Bundle;

typedef struct jwtbundle_Set
{
    //map of bundles
    map_string_jwtbundle_Bundle *bundles;
    //lock
    mtx_t mtx;
} jwtbundle_Set;

jwtbundle_Set* jwtbundle_NewSet(const int n_args, ...);

void jwtbundle_Set_Add(jwtbundle_Set *s, jwtbundle_Bundle *bundle);
void jwtbundle_Set_Remove(jwtbundle_Set *s, const spiffeid_TrustDomain *td);
bool jwtbundle_Set_Has(jwtbundle_Set *s, const spiffeid_TrustDomain *td);
jwtbundle_Bundle* jwtbundle_Set_Get(jwtbundle_Set *s, 
                                    const spiffeid_TrustDomain *td, 
                                    bool *suc);
jwtbundle_Bundle** jwtbundle_Set_Bundles(jwtbundle_Set *s);
uint32_t jwtbundle_Set_Len(jwtbundle_Set *s);
jwtbundle_Bundle* jwtbundle_Set_GetJWTBundleForTrustDomain(
                                    jwtbundle_Set *s, 
                                    const spiffeid_TrustDomain *td, 
                                    err_t *err);

#endif