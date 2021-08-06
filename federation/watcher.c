#include "c-spiffe/federation/watcher.h"

spiffebundle_Watcher *spiffebundle_Watcher_New()
{
    spiffebundle_Watcher *watcher = calloc(1, sizeof(*watcher));
    sh_new_strdup(watcher->endpoints);
    return watcher;
}

void spiffebundle_Watcher_Free(spiffebundle_Watcher *watcher)
{
    if(watcher) {
        for(size_t i = 0, size = shlenu(watcher->endpoints); i < size; ++i) {
            spiffebundle_Endpoint_Free(watcher->endpoints[i].value->endpoint);
            free(watcher->endpoints[i].value->thread);
            free(watcher->endpoints[i].value);
            shdel(watcher->endpoints, watcher->endpoints[i].key);
        }
        shfree(watcher->endpoints);
    }
}

err_t spiffebundle_Watcher_AddHttpsWebEndpoint(
    spiffebundle_Watcher *watcher, const char *url,
    spiffeid_TrustDomain trust_domain)
{
    spiffebundle_Endpoint *endpoint = spiffebundle_Endpoint_New();
    spiffebundle_Endpoint_Status *status
        = (spiffebundle_Endpoint_Status *) calloc(1, sizeof(*status));
    status->endpoint = endpoint;
    status->running = ENDPOINT_STOPPED;
    status->thread = malloc(sizeof(thrd_t));
    status->cond_var = malloc(sizeof(cnd_t));
    int i = cnd_init(status->cond_var);
    err_t error
        = spiffebundle_Endpoint_ConfigHTTPSWEB(endpoint, url, trust_domain);
    if(error == NO_ERROR) {
        shput(watcher->endpoints, trust_domain.name, status);
    } else {
        spiffebundle_Endpoint_Free(endpoint);
        free(status->thread);
        cnd_destroy(status->cond_var);
        free(status->cond_var);
        free(status);
    }
    return error;
}

err_t spiffebundle_Watcher_AddHttpsSpiffeEndpoint(
    spiffebundle_Watcher *watcher, const char *url,
    spiffeid_TrustDomain trust_domain, const char *spiffeid,
    spiffebundle_Source *source)
{
    spiffebundle_Endpoint *endpoint = spiffebundle_Endpoint_New();
    spiffebundle_Endpoint_Status *status = calloc(1, sizeof(*status));
    status->endpoint = endpoint;
    status->thread = malloc(sizeof(thrd_t));
    status->cond_var = malloc(sizeof(cnd_t));
    int i = cnd_init(status->cond_var);
    err_t error = spiffebundle_Endpoint_ConfigHTTPSSPIFFE(
        endpoint, url, trust_domain, spiffeid, source);
    if(error == NO_ERROR) {
        shput(watcher->endpoints, trust_domain.name, status);
    } else {
        spiffebundle_Endpoint_Free(endpoint);
        free(status->thread);
        cnd_destroy(status->cond_var);
        free(status->cond_var);
        free(status);
    }
    return error;
}

spiffebundle_Bundle *spiffebundle_Watcher_GetBundleForTrustDomain(
    spiffebundle_Watcher *watcher, const spiffeid_TrustDomain trust_domain,
    err_t *err)
{
    if(!watcher) {
        *err = ERR_NULL;
        return NULL;
    }
    if(trust_domain.name) {
        spiffebundle_Endpoint_Status *status
            = shget(watcher->endpoints, trust_domain.name);
        if(status == NULL) {
            *err = ERR_NULL;
            return NULL;
        } else {
            *err = NO_ERROR;
            return spiffebundle_Endpoint_GetBundleForTrustDomain(
                status->endpoint, trust_domain, err);
        }

    } else {
        *err = ERR_INVALID_DATA;
        return NULL;
    }
}

// Default refresh time, in seconds
const int DEFAULT_REFRESH_HINT = 300;

static int watch_endpoint(void *arg)
{
    spiffebundle_Endpoint_Status *status
        = (spiffebundle_Endpoint_Status *) arg;

    err_t error = spiffebundle_Endpoint_Fetch(status->endpoint);
    while(error == NO_ERROR && status->running == ENDPOINT_RUNNING) {
        spiffebundle_Bundle *bundle
            = spiffebundle_Endpoint_GetBundleForTrustDomain(
                status->endpoint, status->endpoint->td, &error);
        struct timespec waittime
            = { .tv_sec = DEFAULT_REFRESH_HINT, .tv_nsec = 0 };

        if((bundle->refresh_hint.tv_sec == 0
            && bundle->refresh_hint.tv_nsec > 0)
           || bundle->refresh_hint.tv_sec > 0) {
            waittime = bundle->refresh_hint;
        }

        mtx_lock(&(status->endpoint->mutex));
        if(status->running == ENDPOINT_RUNNING) {
            int t_error = cnd_timedwait(status->cond_var,
                                        &status->endpoint->mutex, &waittime);
            if(t_error == thrd_error) {           // wait broke, cancel thread.
                status->running = ENDPOINT_ERROR; // ERROR STATE
                mtx_unlock(&(status->endpoint->mutex));
                return -1; // cancel thread
            }
        }

        mtx_unlock(&(status->endpoint->mutex));
        if(status->running == ENDPOINT_RUNNING) {
            error = spiffebundle_Endpoint_Fetch(status->endpoint);
        }
    }

    return 0;
}

err_t spiffebundle_Watcher_Start(spiffebundle_Watcher *watcher)
{
    if(watcher) {
        for(size_t i = 0, size = shlenu(watcher->endpoints); i < size; ++i) {
            spiffebundle_Endpoint_Status *status = watcher->endpoints[i].value;
            if(status->running == ENDPOINT_STOPPED && status->thread) {
                status->running = ENDPOINT_RUNNING;
                thrd_create(status->thread, watch_endpoint, status);
            }
        }
        return NO_ERROR;
    }
    return ERR_STARTING;
}

err_t spiffebundle_Watcher_Stop(spiffebundle_Watcher *watcher)
{
    if(watcher) {
        for(size_t i = 0, size = shlenu(watcher->endpoints); i < size; ++i) {
            spiffebundle_Endpoint_Status *status = watcher->endpoints[i].value;
            if(status->running == ENDPOINT_RUNNING) {
                status->running = ENDPOINT_STOPPING;
                spiffebundle_Endpoint_Cancel(status->endpoint);
                cnd_signal(status->cond_var);
            }
        }
        for(size_t i = 0, size = shlenu(watcher->endpoints); i < size; ++i) {
            spiffebundle_Endpoint_Status *status = watcher->endpoints[i].value;
            if(status->running == ENDPOINT_STOPPING && status->thread) {
                thrd_join(*(status->thread), NULL);
                status->running = ENDPOINT_STOPPED;
            }
        }
        return NO_ERROR;
    }
    return ERR_STOPPING;
}

spiffebundle_Endpoint_StatusCode
spiffebundle_Watcher_GetStatus(spiffebundle_Watcher *watcher,
                               const spiffeid_TrustDomain td, err_t *err)
{
    if(!watcher) {
        *err = ERR_NULL;
        return ENDPOINT_ERROR; // not found
    }
    if(td.name) {
        spiffebundle_Endpoint_Status *status
            = shget(watcher->endpoints, td.name);
        if(status == NULL) {
            *err = ERR_NULL;
            return ENDPOINT_ERROR; // not found
        } else {
            *err = NO_ERROR;
            return status->running;
        }
    } else {
        *err = ERR_INVALID_DATA;
        return ENDPOINT_ERROR; // not found
    }
}
