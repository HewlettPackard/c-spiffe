#ifndef __INCLUDE_BUNDLE_JWTBUNDLE_SOURCE_H__
#define __INCLUDE_BUNDLE_JWTBUNDLE_SOURCE_H__

#include "bundle.h"
#include "set.h"

typedef struct jwtbundle_Source
{
    enum jwtbundle_Source_Cardinality
        {JWTBUNDLE_BUNDLE, JWTBUNDLE_SET} type;
    union
    {
        jwtbundle_Bundle *bundle;
        jwtbundle_Set *set;
    } source;
} jwtbundle_Source;

jwtbundle_Bundle* jwtbundle_Source_GetJWTBundleForTrustDomain(
                                    jwtbundle_Source *s,
                                    const spiffeid_TrustDomain td,
                                    err_t *err);

#endif