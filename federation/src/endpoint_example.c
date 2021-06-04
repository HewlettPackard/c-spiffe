#include "endpoint.h"
#include "spiffeid/src/trustdomain.h"

int main()
{
    err_t err = NO_ERROR;
    // Create Endpoint proxy object.
    spiffebundle_Endpoint *endpoint = spiffebundle_Endpoint_New();

    // Configure Endpoint
    // since raw.githubusercontent.com has a bundle installed for it, 
    // the HTTPS call will authenticate.
    spiffebundle_Endpoint_Config_HTTPS_WEB(
        endpoint,
        "https://raw.githubusercontent.com/HewlettPackard/c-spiffe/master/"
        "bundle/jwtbundle/tests/resources/jwk_keys.json",
        spiffeid_TrustDomainFromString("example.com", &err));
    // Fetch it.
    err = spiffebundle_Endpoint_Fetch(endpoint);

    // Get it.
    spiffebundle_Bundle *bundle
        = spiffebundle_Endpoint_GetBundleForTrustDomain(
            endpoint, spiffeid_TrustDomainFromString("example.com", &err),
            &err);

    // Marshall it into a json string
    string_t jwks = spiffebundle_Bundle_Marshal(bundle, &err);

    printf("Trust Domain: %s\n", bundle->td.name);
    printf("Bundle for TD: %s\n", jwks);

    // Free string.
    util_string_t_Free(jwks);

    // don't free spiffebundle since endpoint owns it
    // spiffebundle_Bundle_Free(bundle);

    // Free endpoint
    spiffebundle_Endpoint_Free(endpoint);

    return 0;
}
