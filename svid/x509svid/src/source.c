#include "source.h"

void x509svid_Source_Free(x509svid_Source *source)
{
    if(source) {
        if(source->type == X509SVID_SVID) {
            x509svid_SVID_Free(source->source.svid);
        } else if(source->type == WORKLOADAPI_X509SOURCE_SVID) {
            // workloadapi_X509Source_Free(source->source.source);
        }     

        free(source);
    }
}
