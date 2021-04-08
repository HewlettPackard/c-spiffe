#include "svid/x509svid/src/source.h"

x509svid_Source *x509svid_SourceFromSVID(x509svid_SVID *svid)
{
    if(svid) {
        x509svid_Source *source = malloc(sizeof *source);
        source->type = X509SVID_SVID;
        source->source.svid = svid;

        return source;
    }

    return NULL;
}

x509svid_Source *x509svid_SourceFromSource(workloadapi_X509Source *source)
{
    if(source) {
        x509svid_Source *my_source = malloc(sizeof *my_source);
        my_source->type = WORKLOADAPI_X509SOURCE_SVID;
        my_source->source.source = source;

        return my_source;
    }

    return NULL;
}

x509svid_SVID *x509svid_Source_GetX509SVID(x509svid_Source *source, err_t *err)
{
    x509svid_SVID *svid = NULL;

    if(source) {
        if(source->type == X509SVID_SVID) {
            svid = source->source.svid;
        } else if(source->type == WORKLOADAPI_X509SOURCE_SVID) {
            /// TODO: fix circular dependency
            // svid = workloadapi_X509Source_GetX509SVID(source->source.source,
            //                                           err);
        } else {
            // unknown type
            *err = ERROR2;
        }
    } else {
        // source is NULL
        *err = ERROR1;
    }

    return svid;
}

void x509svid_Source_Free(x509svid_Source *source)
{
    if(source) {
        if(source->type == X509SVID_SVID) {
            x509svid_SVID_Free(source->source.svid);
        } else if(source->type == WORKLOADAPI_X509SOURCE_SVID) {
            /// TODO: fix circular dependency
            // workloadapi_X509Source_Free(source->source.source);
        }

        free(source);
    }
}
