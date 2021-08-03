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

#ifndef INCLUDE_WORKLOAD_JWTSOURCE_H
#define INCLUDE_WORKLOAD_JWTSOURCE_H

#include "c-spiffe/bundle/jwtbundle/set.h"
#include "c-spiffe/svid/jwtsvid/svid.h"
#include "c-spiffe/workload/jwtwatcher.h"
#include <threads.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    workloadapi_JWTWatcherConfig watcher_config;
} workloadapi_JWTSourceConfig;

/** workloadapi_JWTSource is a source of JWT-SVID and JWT bundles maintained
 * via the Workload API
 * */
typedef struct {
    workloadapi_JWTWatcher *watcher;
    workloadapi_JWTSourceConfig *config;
    mtx_t mtx;
    mtx_t closed_mutex;
    bool closed;

    jwtbundle_Set *bundles;
} workloadapi_JWTSource;

/** workloadapi_NewJWTSource creates a new JWTSource. It blocks until the
 * initial update has been received from the Workload API.
 * */
workloadapi_JWTSource *
workloadapi_NewJWTSource(workloadapi_JWTSourceConfig *config, err_t *err);
void workloadapi_JWTSource_Free(workloadapi_JWTSource *source);

err_t workloadapi_JWTSource_Start(workloadapi_JWTSource *source);

/** workloadapi_JWTSource_Close closes the source, dropping the connection to
 * the Workload API. Other source methods will return an error after Close has
 * been called. The underlying Workload API client will also be closed if it is
 * owned by the JWTSource (i.e. not provided via the WithClient option).
 * */
err_t workloadapi_JWTSource_Close(workloadapi_JWTSource *source);

err_t workloadapi_JWTSource_checkClosed(workloadapi_JWTSource *source);

/** workloadapi_JWTSource_WaitUntilUpdated waits until the source is updated or
 * the context is done, in which case ctx.Err() is returned.
 * */
err_t workloadapi_JWTSource_WaitUntilUpdated(workloadapi_JWTSource *source);
void workloadapi_JWTSource_applyJWTBundle_Set(workloadapi_JWTSource *source,
                                              jwtbundle_Set *set);

/** workloadapi_JWTSource_GetJWTSVID gettes a JWT-SVID from the source with the
 * given parameters. It implements the jwtsvid.Source interface.
 * */
jwtsvid_SVID *workloadapi_JWTSource_GetJWTSVID(workloadapi_JWTSource *source,
                                               jwtsvid_Params *params,
                                               err_t *err);

/** workloadapi_JWTSource_GetJWTBundleForTrustDomain returns the JWT bundle for
 * the given trust domain. It implements the jwtbundle.Source interface.
 * */
jwtbundle_Bundle *workloadapi_JWTSource_GetJWTBundleForTrustDomain(
    workloadapi_JWTSource *source, const spiffeid_TrustDomain td, err_t *err);

#ifdef __cplusplus
}
#endif

#endif // INCLUDE_WORKLOAD_JWTSOURCE_H
