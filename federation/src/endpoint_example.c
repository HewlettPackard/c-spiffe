#include "endpoint.h"
#include "spiffeid/src/trustdomain.h"

int main()
{
    err_t err = NO_ERROR;
    spiffebundle_Endpoint *endpoint = spiffebundle_Endpoint_New();
    /// TODO: find a spiffe bundle endpoint.
    spiffebundle_Endpoint_Config_HTTPS_WEB(
        endpoint,
        "https://raw.githubusercontent.com/HewlettPackard/c-spiffe/master/"
        "bundle/jwtbundle/tests/resources/jwk_keys.json",
        spiffeid_TrustDomainFromString("example.com", &err));

    err = spiffebundle_Endpoint_Fetch(endpoint);
    spiffebundle_Bundle *bundle
        = spiffebundle_Endpoint_GetBundleForTrustDomain(
            endpoint, spiffeid_TrustDomainFromString("example.com", &err),
            &err);

    printf("pBundle: %p\n", bundle);

    printf("td: %s\n", bundle->td.name);
    return 0;
}
