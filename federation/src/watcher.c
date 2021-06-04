#include "watcher.h"

spiffebundle_Watcher *spiffebundle_Watcher_New()
{
    spiffebundle_Watcher *watcher
        = (spiffebundle_Watcher *) calloc(1, sizeof(*watcher));
    watcher->endpoints = NULL; // empty map
    return watcher;
}

void spiffebundle_Watcher_Free(spiffebundle_Watcher *watcher)
{
    if(watcher) {
        for(size_t i = 0, length = shlenu(watcher->endpoints); i < length;
            ++i) {
            spiffebundle_Endpoint_Free(watcher->endpoints[i].value);
            util_string_t_Free(watcher->endpoints[i].key);
        }
        shfree(watcher->endpoints);
    }
}

err_t spiffebundle_Watcher_Add_HTTPS_WEB_Endpoint(
    spiffebundle_Watcher *watcher, const char *url,
    spiffeid_TrustDomain trust_domain)
{
    spiffebundle_Endpoint *endpoint = spiffebundle_Endpoint_New();
    err_t error
        = spiffebundle_Endpoint_Config_HTTPS_WEB(endpoint, url, trust_domain);
    if(error == NO_ERROR) {
        shput(watcher->endpoints, trust_domain.name, endpoint);
    } else {
        spiffebundle_Endpoint_Free(endpoint);
    }
    return error;
}

err_t spiffebundle_Watcher_Add_HTTPS_SPIFFE_Endpoint(
    spiffebundle_Watcher *watcher, const char *url,
    spiffeid_TrustDomain trust_domain, string_t spiffeid,
    spiffebundle_Source *source)
{
    spiffebundle_Endpoint *endpoint = spiffebundle_Endpoint_New();
    err_t error = spiffebundle_Endpoint_Config_HTTPS_SPIFFE(
        endpoint, url, trust_domain, spiffeid, source);
    if(error == NO_ERROR) {
        shput(watcher->endpoints, trust_domain.name, endpoint);
    } else {
        spiffebundle_Endpoint_Free(endpoint);
    }
    return error;
}

err_t spiffebundle_Watcher_Start(spiffebundle_Watcher *watcher) {}

spiffebundle_Bundle *
spiffebundle_Watcher_GetBundleForTrustDomain(spiffebundle_Watcher *watcher,
                                             spiffeid_TrustDomain trust_domain,
                                             err_t *err)
{
    if(!watcher){
        *err = ERROR1;
        return NULL;
    }
    if(trust_domain.name) {
        spiffebundle_Endpoint *endpoint
            = shgetp_null(watcher->endpoints, trust_domain.name);
        if(endpoint == NULL) {
            *err = ERROR3;
            return NULL;
        } else {
            *err = NO_ERROR;
            return spiffebundle_Endpoint_GetBundleForTrustDomain(
                endpoint, trust_domain, err);
        }

    } else {
        *err = ERROR2;
        return NULL;
    }
}
