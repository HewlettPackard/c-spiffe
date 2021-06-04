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
