
/**

(C) Copyright 2020-2021 Hewlett Packard Enterprise Development LP

 

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

 

    http://www.apache.org/licenses/LICENSE-2.0

 

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.

**/

#include "c-spiffe/svid/x509svid/source.h"

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
        my_source->type = X509SVID_WORKLOADAPI_X509SOURCE;
        my_source->source.source = source;

        return my_source;
    }

    return NULL;
}

x509svid_SVID *x509svid_Source_GetX509SVID(x509svid_Source *source, err_t *err)
{
    x509svid_SVID *svid = NULL;
    *err = NO_ERROR;

    if(source) {
        if(source->type == X509SVID_SVID) {
            svid = source->source.svid;
        } else if(source->type == X509SVID_WORKLOADAPI_X509SOURCE) {
            svid = workloadapi_X509Source_GetX509SVID(source->source.source,
                                                      err);
        } else {
            // unknown type
            *err = ERR_UNKNOWN_TYPE;
        }
    } else {
        // source is NULL
        *err = ERR_NULL;
    }

    return svid;
}

void x509svid_Source_Free(x509svid_Source *source)
{
    if(source) {
        if(source->type == X509SVID_SVID) {
            x509svid_SVID_Free(source->source.svid);
        } else if(source->type == X509SVID_WORKLOADAPI_X509SOURCE) {
            workloadapi_X509Source_Free(source->source.source);
        }

        free(source);
    }
}
