#include "c-spiffe/bundle/spiffebundle/source.h"

spiffebundle_Bundle *spiffebundle_Source_GetSpiffeBundleForTrustDomain(
    spiffebundle_Source *s, const spiffeid_TrustDomain td, err_t *err)
{
    if(s) {
        if(s->type == SPIFFEBUNDLE_BUNDLE) {
            return spiffebundle_Bundle_GetBundleForTrustDomain(
                s->source.bundle, td, err);
        } else if(s->type == SPIFFEBUNDLE_SET) {
            return spiffebundle_Set_GetBundleForTrustDomain(s->source.set, td,
                                                            err);
        } else if(s->type == SPIFFEBUNDLE_ENDPOINT) {
            return spiffebundle_Endpoint_GetBundleForTrustDomain(
                s->source.endpoint, td, err);
        }
    } else {
        *err = ERR_GET;
        return NULL;
    }
}

spiffebundle_Source *spiffebundle_SourceFromBundle(spiffebundle_Bundle *b)
{
    if(b) {
        spiffebundle_Source *source = malloc(sizeof *source);

        source->type = SPIFFEBUNDLE_BUNDLE;
        source->source.bundle = b;

        return source;
    }

    return NULL;
}

spiffebundle_Source *spiffebundle_SourceFromSet(spiffebundle_Set *s)
{
    if(s) {
        spiffebundle_Source *source = malloc(sizeof *source);
        source->type = SPIFFEBUNDLE_SET;
        source->source.set = s;

        return source;
    }

    return NULL;
}

spiffebundle_Source *
spiffebundle_SourceFromEndpoint(spiffebundle_Endpoint *endpoint)
{
    if(endpoint) {
        spiffebundle_Source *my_source = malloc(sizeof *my_source);
        my_source->type = SPIFFEBUNDLE_ENDPOINT;
        my_source->source.endpoint = endpoint;

        return my_source;
    }

    return NULL;
}

void spiffebundle_Source_Free(spiffebundle_Source *s)
{
    if(s) {
        if(s->type == SPIFFEBUNDLE_BUNDLE) {
            spiffebundle_Bundle_Free(s->source.bundle);
        } else if(s->type == SPIFFEBUNDLE_SET) {
            spiffebundle_Set_Free(s->source.set);
        } else if(s->type == SPIFFEBUNDLE_ENDPOINT) {
            spiffebundle_Endpoint_Free(s->source.endpoint);
        }
        free(s);
    }
}
