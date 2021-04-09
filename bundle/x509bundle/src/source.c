#include "bundle/x509bundle/src/source.h"

x509bundle_Bundle *x509bundle_Source_GetX509BundleForTrustDomain(
    x509bundle_Source *s, const spiffeid_TrustDomain td, err_t *err)
{
    if(s->type == X509BUNDLE_BUNDLE) {
        return x509bundle_Bundle_GetX509BundleForTrustDomain(s->source.bundle,
                                                             td, err);
    } else if(s->type == X509BUNDLE_SET) {
        return x509bundle_Set_GetX509BundleForTrustDomain(s->source.set, td,
                                                          err);
    }

    return NULL;
}

x509bundle_Source *x509bundle_SourceFromBundle(x509bundle_Bundle *b)
{
    if(b) {
        x509bundle_Source *source = malloc(sizeof *source);

        source->type = X509BUNDLE_BUNDLE;
        source->source.bundle = b;

        return source;
    }

    return NULL;
}

x509bundle_Source *x509bundle_SourceFromSet(x509bundle_Set *s)
{
    if(s) {
        x509bundle_Source *source = malloc(sizeof *source);
        source->type = X509BUNDLE_SET;
        source->source.set = s;

        return source;
    }

    return NULL;
}

x509bundle_Source *x509bundle_SourceFromSource(workloadapi_X509Source *source)
{
    if(source) {
        x509bundle_Source *my_source = malloc(sizeof *my_source);
        my_source->type = WORKLOADAPI_X509SOURCE;
        my_source->source.source = source;

        return my_source;
    }

    return NULL;
}


void x509bundle_Source_Free(x509bundle_Source *s)
{
    if(s) {
        if(s->type == X509BUNDLE_BUNDLE) {
            x509bundle_Bundle_Free(s->source.bundle);
        } else if(s->type == X509BUNDLE_SET) {
            x509bundle_Set_Free(s->source.set);
        }

        free(s);
    }
}
