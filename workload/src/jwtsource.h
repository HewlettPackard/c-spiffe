#ifndef INCLUDE_WORKLOAD_JWTSOURCE_H
#define INCLUDE_WORKLOAD_JWTSOURCE_H

#include "../../bundle/jwtbundle/src/set.h"
#include "../../svid/jwtsvid/src/svid.h"
#include "jwtwatcher.h"
#include "jwtcallback.h"
#include <threads.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    workloadapi_JWTWatcherConfig watcher_config;
} workloadapi_JWTSourceConfig;

typedef struct {
    workloadapi_JWTWatcher *watcher;
    workloadapi_JWTSourceConfig *config;
    mtx_t mtx;
    mtx_t closed_mutex;
    bool closed;

    jwtbundle_Set *bundles;
} workloadapi_JWTSource;

workloadapi_JWTSource *
workloadapi_NewJWTSource(workloadapi_JWTSourceConfig *config, err_t *err);
void workloadapi_JWTSource_Free(workloadapi_JWTSource *source);

err_t workloadapi_JWTSource_Start(workloadapi_JWTSource *source);
err_t workloadapi_JWTSource_Close(workloadapi_JWTSource *source);

err_t workloadapi_JWTSource_checkClosed(workloadapi_JWTSource *source);

err_t workloadapi_JWTSource_WaitUntilUpdated(workloadapi_JWTSource *source);
void workloadapi_JWTSource_applyJWTBundle_Set(workloadapi_JWTSource *source,
                                             jwtbundle_Set *set);

jwtsvid_SVID *
workloadapi_JWTSource_GetJWTSVID(workloadapi_JWTSource *source, jwtsvid_Params* params, err_t *err);

jwtbundle_Bundle *workloadapi_JWTSource_GetJWTBundleForTrustDomain(
    workloadapi_JWTSource *source, spiffeid_TrustDomain *td, err_t *err);

#ifdef __cplusplus
}
#endif

#endif // INCLUDE_WORKLOAD_JWTSOURCE_H
