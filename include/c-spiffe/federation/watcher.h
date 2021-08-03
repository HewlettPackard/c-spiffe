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

#ifndef INCLUDE_FEDERATION_WATCHER_H
#define INCLUDE_FEDERATION_WATCHER_H

#include "c-spiffe/bundle/spiffebundle/bundle.h"
#include "c-spiffe/bundle/spiffebundle/source.h"
#include "c-spiffe/federation/endpoint.h"
#include "c-spiffe/spiffeid/trustdomain.h"
#include "c-spiffe/utils/util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum spiffebundle_Endpoint_StatusCode {
    ENDPOINT_ERROR = -2,
    ENDPOINT_STOPPING = -1,
    ENDPOINT_STOPPED = 0,
    ENDPOINT_RUNNING = 1
} spiffebundle_Endpoint_StatusCode;

typedef struct spiffebundle_Endpoint_Status {
    spiffebundle_Endpoint *endpoint;
    cnd_t *cond_var;
    thrd_t *thread;
    spiffebundle_Endpoint_StatusCode running;
} spiffebundle_Endpoint_Status;

typedef struct map_string_Endpoint_Status {
    string_t key;
    spiffebundle_Endpoint_Status *value;
} map_string_Endpoint_Status;

typedef struct spiffebundle_Watcher {
    map_string_Endpoint_Status *endpoints;
} spiffebundle_Watcher;

// creates watcher
spiffebundle_Watcher *spiffebundle_Watcher_New();
// frees watcher
void spiffebundle_Watcher_Free(spiffebundle_Watcher *watcher);

// Add an endpoint to the watcher, will create a spiffebundle_Endpoint
// internally, and set it up. https_web protocol
err_t spiffebundle_Watcher_AddHttpsWebEndpoint(
    spiffebundle_Watcher *watcher, const char *url,
    spiffeid_TrustDomain trust_domain);
// https_spiffe protocol
err_t spiffebundle_Watcher_AddHttpsSpiffeEndpoint(
    spiffebundle_Watcher *watcher, const char *url,
    spiffeid_TrustDomain trust_domain, const char *spiffeid,
    spiffebundle_Source *source);

// remove endpoint, will free the endpoint
err_t spiffebundle_Watcher_RemoveEndpoint(spiffebundle_Watcher *watcher,
                                          spiffeid_TrustDomain trust_domain);

// starts watcher, will spawn a thread for each endpoint set up.
err_t spiffebundle_Watcher_Start(spiffebundle_Watcher *watcher);

// stops watcher, will stop each endpoint thread active.
err_t spiffebundle_Watcher_Stop(spiffebundle_Watcher *watcher);

// gets a bundle for the Trust Domain from the watcher, will return NULL if
// bundle is not found.
spiffebundle_Bundle *spiffebundle_Watcher_GetBundleForTrustDomain(
    spiffebundle_Watcher *watcher, const spiffeid_TrustDomain td, err_t *err);

// returns the running status for an endpoint.
spiffebundle_Endpoint_StatusCode
spiffebundle_Watcher_GetStatus(spiffebundle_Watcher *watcher,
                               const spiffeid_TrustDomain td, err_t *err);

#ifdef __cplusplus
}
#endif

#endif // INCLUDE_FEDERATION_WATCHER_H
