
/**

(C) Copyright 2020-2021 Hewlett Packard Enterprise Development LP

 

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

 

    http://www.apache.org/licenses/LICENSE-2.0

 

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.

**/

#include "c-spiffe/federation/endpoint.h"
#include "c-spiffe/spiffeid/trustdomain.h"

int main()
{
    err_t err = NO_ERROR;
    // Create Endpoint proxy object.
    spiffebundle_Endpoint *endpoint = spiffebundle_Endpoint_New();

    // Configure Endpoint
    // since raw.githubusercontent.com has a bundle installed for it,
    // the HTTPS call will authenticate.
    spiffeid_TrustDomain td
        = spiffeid_TrustDomainFromString("example.com", &err);
    spiffebundle_Endpoint_ConfigHTTPSWEB(
        endpoint,
        "https://raw.githubusercontent.com/HewlettPackard/c-spiffe/master/"
        "bundle/jwtbundle/tests/resources/jwk_keys.json",
        td);
    // Fetch it.
    err = spiffebundle_Endpoint_Fetch(endpoint);

    // Get it.
    spiffebundle_Bundle *bundle
        = spiffebundle_Endpoint_GetBundleForTrustDomain(endpoint, td, &err);

    // Marshall it into a json string
    string_t jwks = spiffebundle_Bundle_Marshal(bundle, &err);

    printf("Trust Domain: %s\n", bundle->td.name);
    printf("Bundle for TD: %s\n", jwks);

    // Free string.
    util_string_t_Free(jwks);
    spiffeid_TrustDomain_Free(&td);
    // don't free spiffebundle since endpoint owns it
    // spiffebundle_Bundle_Free(bundle);

    // Free endpoint
    spiffebundle_Endpoint_Free(endpoint);

    return 0;
}
