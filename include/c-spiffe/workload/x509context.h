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

#ifndef INCLUDE_WORKLOAD_X509CONTEXT_H
#define INCLUDE_WORKLOAD_X509CONTEXT_H

#include "c-spiffe/bundle/x509bundle/set.h"
#include "c-spiffe/svid/x509svid/svid.h"

#ifdef __cplusplus
extern "C" {
#endif

/** workloadapi_X509Context conveys X.509 materials from the Workload API.
 * */
typedef struct {
    x509svid_SVID **svids;
    /* Bundles is a set of X.509 bundles. */
    x509bundle_Set *bundles;

} workloadapi_X509Context;

/** type for callback function. will be set by X509Source. */
typedef void (*workloadapi_x509ContextFunc_t)(workloadapi_X509Context *,
                                              void *);
// eg.:
// workloadapi_x509ContextFunc_t func; -> void
// (*func)(workloadapi_X509Context* updatedContext);

typedef struct {
    void *args;
    workloadapi_x509ContextFunc_t func;
} workloadapi_X509Callback;

#ifdef __cplusplus
}
#endif

#endif // INCLUDE_WORKLOAD_X509CONTEXT_H
