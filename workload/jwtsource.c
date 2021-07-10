#include "c-spiffe/workload/jwtsource.h"
#include "c-spiffe/workload/jwtwatcher.h"

void workloadapi_JWTSource_onJWTBundle_SetCallback(jwtbundle_Set *jwt_set,
                                                   void *args)
{
    workloadapi_JWTSource *source = (workloadapi_JWTSource *) args;
    workloadapi_JWTSource_applyJWTBundle_Set(source, jwt_set);
}

workloadapi_JWTSource *
workloadapi_NewJWTSource(workloadapi_JWTSourceConfig *config, err_t *err)
{
    if(!config) {
        config = (workloadapi_JWTSourceConfig *) malloc(sizeof *config);
        memset(config, 0, sizeof *config);
    }

    workloadapi_JWTSource *source
        = (workloadapi_JWTSource *) malloc(sizeof *source);
    source->closed = true;
    mtx_init(&(source->mtx), mtx_plain);
    mtx_init(&(source->closed_mutex), mtx_plain);
    source->bundles = NULL;
    source->config = config;
    if(!source->config->watcher_config.client_options) {
        arrpush(source->config->watcher_config.client_options,
                workloadapi_Client_defaultOptions);
    }
    workloadapi_JWTCallback cb
        = { .args = source,
            .func = workloadapi_JWTSource_onJWTBundle_SetCallback };
    source->watcher
        = workloadapi_newJWTWatcher(source->config->watcher_config, cb, err);
    if((*err)) {
        workloadapi_JWTSource_Free(source);
        return NULL;
    }

    return source;
}

// blocks until first SVID update is received
err_t workloadapi_JWTSource_Start(workloadapi_JWTSource *source)
{
    if(!source) {
        return ERR_NULL;
    }
    mtx_lock(&(source->closed_mutex));
    source->closed = false;
    mtx_unlock(&(source->closed_mutex));
    err_t err = workloadapi_JWTWatcher_Start(
        source->watcher); // blocks until first update
    return err;
}

err_t workloadapi_JWTSource_Close(workloadapi_JWTSource *source)
{
    mtx_lock(&(source->closed_mutex));
    source->closed = true;
    mtx_unlock(&(source->closed_mutex));

    return workloadapi_JWTWatcher_Close(source->watcher);
}

jwtsvid_SVID *workloadapi_JWTSource_GetJWTSVID(workloadapi_JWTSource *source,
                                               jwtsvid_Params *params,
                                               err_t *err)
{
    *err = workloadapi_JWTSource_checkClosed(source);
    if(!(*err)) {
        return workloadapi_Client_FetchJWTSVID(source->watcher->client, params,
                                               err);
    }
    return NULL;
}

jwtbundle_Bundle *workloadapi_JWTSource_GetJWTBundleForTrustDomain(
    workloadapi_JWTSource *source, const spiffeid_TrustDomain td, err_t *err)
{
    *err = workloadapi_JWTSource_checkClosed(source);
    if(!(*err)) {
        jwtbundle_Bundle *bundle = jwtbundle_Set_GetJWTBundleForTrustDomain(
            source->bundles, td, err);
        if(*err == ERR_TRUSTDOMAIN_NOTAVAILABLE) {
            *err = ERR_INVALID_TRUSTDOMAIN;
        }
        return bundle;
    }
    return NULL;
}

err_t workloadapi_JWTSource_WaitUntilUpdated(workloadapi_JWTSource *source)
{
    return workloadapi_JWTWatcher_WaitUntilUpdated(source->watcher);
}

void workloadapi_JWTSource_applyJWTBundle_Set(workloadapi_JWTSource *source,
                                              jwtbundle_Set *set)
{
    mtx_lock(&(source->mtx));
    jwtbundle_Set_Free(source->bundles);
    source->bundles = jwtbundle_Set_Clone(set);
    mtx_unlock(&(source->mtx));
}

err_t workloadapi_JWTSource_checkClosed(workloadapi_JWTSource *source)
{
    err_t err = NO_ERROR;
    mtx_lock(&(source->closed_mutex));
    if(source->closed) {
        // source is closed
        err = ERR_CLOSED;
    }
    mtx_unlock(&(source->closed_mutex));
    return err;
}

void workloadapi_JWTSource_Free(workloadapi_JWTSource *source)
{
    if(source) {
        mtx_lock(&(source->mtx));
        jwtbundle_Set_Free(source->bundles);
        if(source->watcher)
            workloadapi_JWTWatcher_Free(source->watcher);
        if(source->config)
            free(source->config);
        mtx_unlock(&(source->mtx));
        free(source);
    }
}
