
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
