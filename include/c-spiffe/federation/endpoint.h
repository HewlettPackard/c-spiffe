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

#ifndef INCLUDE_FEDERATION_ENDPOINT_H
#define INCLUDE_FEDERATION_ENDPOINT_H

#include "c-spiffe/bundle/spiffebundle/bundle.h"
#include "c-spiffe/bundle/spiffebundle/source.h"
#include "c-spiffe/spiffeid/id.h"
#include "c-spiffe/spiffeid/trustdomain.h"
#include "c-spiffe/utils/util.h"
#include <curl/curl.h>
#include <threads.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct spiffebundle_Source spiffebundle_Source;

typedef enum spiffebundle_Endpoint_Profile {
    NONE = 0,
    HTTPS_WEB,
    HTTPS_SPIFFE
} spiffebundle_Endpoint_Profile;

typedef struct spiffebundle_Endpoint {
    string_t url;
    spiffebundle_Endpoint_Profile profile;
    spiffeid_TrustDomain td;
    spiffeid_ID id;
    spiffebundle_Source *source;
    bool owns_bundle;
    CURL *curl_handle;
    mtx_t mutex;
} spiffebundle_Endpoint;

spiffebundle_Endpoint *spiffebundle_Endpoint_New();
void spiffebundle_Endpoint_Free(spiffebundle_Endpoint *endpoint);

err_t spiffebundle_Endpoint_ConfigHTTPSWEB(spiffebundle_Endpoint *endpoint,
                                           const char *url,
                                           spiffeid_TrustDomain trust_domain);

err_t spiffebundle_Endpoint_ConfigHTTPSSPIFFE(
    spiffebundle_Endpoint *endpoint, const char *url,
    spiffeid_TrustDomain trust_domain, const char *spiffeid,
    spiffebundle_Source *source);

err_t spiffebundle_Endpoint_Fetch(spiffebundle_Endpoint *endpoint);

// cancels any running curl request, sets curl handler to NULL
err_t spiffebundle_Endpoint_Cancel(spiffebundle_Endpoint *endpoint);

spiffebundle_Bundle *
spiffebundle_Endpoint_GetBundleForTrustDomain(spiffebundle_Endpoint *endpoint,
                                              const spiffeid_TrustDomain td,
                                              err_t *err);

#ifdef __cplusplus
}
#endif

#endif // INCLUDE_FEDERATION_ENDPOINT_H
