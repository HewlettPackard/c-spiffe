#include "endpoint.h"

spiffebundle_Endpoint *spiffebundle_Endpoint_New()
{
    spiffebundle_Endpoint *endpoint
        = (spiffebundle_Endpoint *) calloc(1, sizeof(*endpoint));
    endpoint->bundle = NULL;
    endpoint->trust_domain.name = NULL;
    endpoint->url = NULL;
    endpoint->profile = NONE;
    return endpoint;
}

void spiffebundle_Endpoint_Free(spiffebundle_Endpoint *endpoint)
{
    if(endpoint) {
        spiffebundle_Bundle_Free(endpoint->bundle);
        if(endpoint->url) {
            util_string_t_Free(endpoint->url);
        }
        if(endpoint->trust_domain.name){
            util_string_t_Free(endpoint->trust_domain.name);
        }
        if(endpoint->spiffeID){
            spiffeid_ID_Free(endpoint->spiffeID);
        }
        free(endpoint);
    }
}

err_t spiffebundle_Endpoint_Config_HTTPS_WEB(spiffebundle_Endpoint *endpoint,
                                             string_t url,
                                             spiffeid_TrustDomain trust_domain)
{
    if(!endpoint) {
        return ERROR1;
    }
    if(!url) {
        return ERROR2;
    }
    if(!trust_domain.name) {
        return ERROR3;
    }
    endpoint->url = string_new(url);
    endpoint->trust_domain = trust_domain;
    endpoint->trust_domain.name = string_new(trust_domain.name);
    endpoint->profile = HTTPS_WEB;
    return NO_ERROR;
}

err_t spiffebundle_Endpoint_Config_HTTPS_SPIFFE(
    spiffebundle_Endpoint *endpoint, string_t url,
    spiffeid_TrustDomain trust_domain, spiffeid_ID spiffeid,
    spiffebundle_Source *source){

    }

err_t spiffebundle_Endpoint_Fetch(spiffebundle_Endpoint *endpoint);
spiffebundle_Bundle *spiffebundle_Endpoint_GetBundleForTrustDomain(
    spiffebundle_Endpoint *endpoint, spiffeid_TrustDomain trust_domain,
    err_t *err){

    }
