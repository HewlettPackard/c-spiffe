#include "bundle/jwtbundle/src/source.h"

jwtbundle_Bundle *jwtbundle_Source_GetJWTBundleForTrustDomain(
    jwtbundle_Source *s, const spiffeid_TrustDomain td, err_t *err)
{
    if(s->type == JWTBUNDLE_BUNDLE) {
        return jwtbundle_Bundle_GetJWTBundleForTrustDomain(s->source.bundle,
                                                           td, err);
    } else if(s->type == JWTBUNDLE_SET) {
        return jwtbundle_Set_GetJWTBundleForTrustDomain(s->source.set, td,
                                                        err);
    }

    return NULL;
}

jwtbundle_Source *jwtbundle_SourceFromBundle(jwtbundle_Bundle *b)
{
    if(b) {
        jwtbundle_Source *source = malloc(sizeof *source);

        source->type = JWTBUNDLE_BUNDLE;
        source->source.bundle = b;

        return source;
    }

    return NULL;
}

jwtbundle_Source *jwtbundle_SourceFromSet(jwtbundle_Set *s)
{
    if(s) {
        jwtbundle_Source *source = malloc(sizeof *source);

        source->type = JWTBUNDLE_SET;
        source->source.set = s;

        return source;
    }

    return NULL;
}

void jwtbundle_Source_Free(jwtbundle_Source *s)
{
    if(s) {
        if(s->type == JWTBUNDLE_BUNDLE) {
            jwtbundle_Bundle_Free(s->source.bundle);
        } else if(s->type == JWTBUNDLE_SET) {
            jwtbundle_Set_Free(s->source.set);
        }

        free(s);
    }
}
