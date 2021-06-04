#include "watcher.h"

spiffebundle_Watcher *spiffebundle_Watcher_New()
{
    spiffebundle_Watcher *watcher
        = (spiffebundle_Watcher *) calloc(1, sizeof(*watcher));
    sh_new_strdup(watcher->endpoints);
    return watcher;
}

void spiffebundle_Watcher_Free(spiffebundle_Watcher *watcher)
{
    if(watcher) {
        for(size_t i = 0, length = shlenu(watcher->endpoints); i < length;
            ++i) {
            spiffebundle_Endpoint_Free(watcher->endpoints[i].value->endpoint);
            free(watcher->endpoints[i].value);
            shdel(watcher->endpoints,watcher->endpoints[i].key);
        }
        shfree(watcher->endpoints);
    }
}

err_t spiffebundle_Watcher_AddHttpsWebEndpoint(
    spiffebundle_Watcher *watcher, const char *url,
    spiffeid_TrustDomain trust_domain)
{
    spiffebundle_Endpoint *endpoint = spiffebundle_Endpoint_New();
    spiffebundle_Endpoint_Status* status = (spiffebundle_Endpoint_Status*) calloc(1,sizeof(*status));
    status->endpoint = endpoint;
    status->running = false;
    err_t error
        = spiffebundle_Endpoint_ConfigHTTPSWEB(endpoint, url, trust_domain);
    if(error == NO_ERROR) {
        shput(watcher->endpoints, trust_domain.name, status);
    } else {
        spiffebundle_Endpoint_Free(endpoint);
        free(status);
    }
    return error;
}

err_t spiffebundle_Watcher_AddHttpsSpiffeEndpoint(
    spiffebundle_Watcher *watcher, const char *url,
    spiffeid_TrustDomain trust_domain, const char* spiffeid,
    spiffebundle_Source *source)
{
    spiffebundle_Endpoint *endpoint = spiffebundle_Endpoint_New();
    spiffebundle_Endpoint_Status* status = (spiffebundle_Endpoint_Status*) calloc(1,sizeof(*status));
    status->endpoint = endpoint;
    status->running = false;
    err_t error = spiffebundle_Endpoint_ConfigHTTPSSPIFFE(
        endpoint, url, trust_domain, spiffeid, source);
    if(error == NO_ERROR) {
        shput(watcher->endpoints, trust_domain.name, status);
    } else {
        spiffebundle_Endpoint_Free(endpoint);
        free(status);
    }
    return error;
}

spiffebundle_Bundle *
spiffebundle_Watcher_GetBundleForTrustDomain(spiffebundle_Watcher *watcher,
                                             spiffeid_TrustDomain trust_domain,
                                             err_t *err)
{
    if(!watcher) {
        *err = ERROR1;
        return NULL;
    }
    if(trust_domain.name) {
        spiffebundle_Endpoint_Status *status
            = shget(watcher->endpoints, trust_domain.name);
        if(status == NULL) {
            *err = ERROR3;
            return NULL;
        } else {
            *err = NO_ERROR;
            return spiffebundle_Endpoint_GetBundleForTrustDomain(
                status->endpoint, trust_domain, err);
        }

    } else {
        *err = ERROR2;
        return NULL;
    }
}

const int DEFAULT_REFRESH_HINT = 300;

void *watch_endpoint(void *arg){
    spiffebundle_Endpoint *endpoint = (spiffebundle_Endpoint*) arg;
    err_t error = spiffebundle_Endpoint_Fetch(endpoint);
    while(error == NO_ERROR){
        spiffebundle_Bundle *bundle = spiffebundle_Endpoint_GetBundleForTrustDomain(endpoint,endpoint->td,&error);
        struct timespec waittime= {.tv_sec = DEFAULT_REFRESH_HINT,.tv_nsec = 0};
        
        if(bundle->refresh_hint.tv_sec > 0 || bundle->refresh_hint.tv_sec > 0 && bundle->refresh_hint.tv_nsec > 0){
            waittime = bundle->refresh_hint;
        }

        ///TODO: wait for refresh_hint duration
        ///TODO: or wait for stop signal

        error = spiffebundle_Endpoint_Fetch(endpoint);
    }
}

err_t spiffebundle_Watcher_Start(spiffebundle_Watcher *watcher)
{
    if(watcher) {
        for(size_t i = 0, length = shlenu(watcher->endpoints); i < length;
            ++i) {
                if(!watcher->endpoints[i].value->running){
                    pthread_create(watcher->endpoints[i].value->thread, NULL, watch_endpoint,
                           watcher->endpoints[i].value);
                }
            
        }
        return NO_ERROR;
    }
    return ERROR1;
}

err_t spiffebundle_Watcher_Stop(spiffebundle_Watcher *watcher) {}
