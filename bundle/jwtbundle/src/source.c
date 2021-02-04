#include "source.h"

jwtbundle_Bundle* jwtbundle_Source_GetJWTBundleForTrustDomain(
                                    jwtbundle_Source *s,
                                    const spiffeid_TrustDomain td,
                                    err_t *err)
{
    if(s->type == JWTBUNDLE_BUNDLE)
    {
        return jwtbundle_Bundle_GetJWTBundleForTrustDomain(
            s->source.bundle, td, err);
    }
    else if(s->type == JWTBUNDLE_SET)
    {
        return jwtbundle_Set_GetJWTBundleForTrustDomain(
            s->source.set, td, err);
    }

    return NULL;
}