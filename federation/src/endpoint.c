#include "endpoint.h"

spiffebundle_Endpoint *spiffebundle_Endpoint_New()
{
    spiffebundle_Endpoint *endpoint
        = (spiffebundle_Endpoint *) calloc(1, sizeof(*endpoint));
    endpoint->bundle_source = NULL;
    endpoint->owns_bundle = false;
    endpoint->trust_domain.name = NULL;
    endpoint->url = NULL;
    endpoint->profile = NONE;
    return endpoint;
}

void spiffebundle_Endpoint_Free(spiffebundle_Endpoint *endpoint)
{
    if(endpoint) {
        if(endpoint->owns_bundle) {
            spiffebundle_Source_Free(endpoint->bundle_source);
            endpoint->owns_bundle = false;
        }
        if(endpoint->url) {
            util_string_t_Free(endpoint->url);
        }
        if(endpoint->trust_domain.name) {
            util_string_t_Free(endpoint->trust_domain.name);
        }
        if(!spiffeid_ID_IsZero(endpoint->spiffe_id)) {
            spiffeid_ID_Free(&endpoint->spiffe_id);
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
    endpoint->owns_bundle = false;
    return NO_ERROR;
}

err_t spiffebundle_Endpoint_Config_HTTPS_SPIFFE(
    spiffebundle_Endpoint *endpoint, string_t url,
    spiffeid_TrustDomain trust_domain, spiffeid_ID spiffe_id,
    spiffebundle_Source *source)
{
    err_t err = NO_ERROR;
    endpoint->spiffe_id
        = spiffeid_FromString(spiffeid_ID_String(spiffe_id), &err);
    if(err){
        return ERROR4; // couldn't parse spiffeID
    }
    if(!endpoint) {
        return ERROR1; // NULL endpoint pointer
    }
    if(!url) {
        return ERROR2; // empty/NULL url string
    }
    if(!trust_domain.name) {
        return ERROR3; // empty/NULL trust domain name
    }
    endpoint->url = string_new(url);
    endpoint->trust_domain = trust_domain;
    endpoint->trust_domain.name = string_new(trust_domain.name);
    endpoint->profile = HTTPS_SPIFFE;
    endpoint->owns_bundle = false;
    endpoint->bundle_source = source;
    return NO_ERROR;
}

err_t spiffebundle_Endpoint_Fetch(spiffebundle_Endpoint *endpoint);
spiffebundle_Bundle *spiffebundle_Endpoint_GetBundleForTrustDomain(
    spiffebundle_Endpoint *endpoint, spiffeid_TrustDomain trust_domain,
    err_t *err)
{}
