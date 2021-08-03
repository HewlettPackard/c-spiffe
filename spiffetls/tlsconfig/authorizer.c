
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

#include "c-spiffe/spiffetls/tlsconfig/authorizer.h"

match_err_t tlsconfig_ApplyAuthorizer(tlsconfig_Authorizer *authorizer,
                                      const spiffeid_ID id, X509 ***certified)
{
    authorizer->certified_chains = certified;
    return spiffeid_ApplyMatcher(authorizer->matcher, id);
}

tlsconfig_Authorizer *tlsconfig_AuthorizeAny()
{
    tlsconfig_Authorizer *authorizer = malloc(sizeof *authorizer);

    authorizer->certified_chains = NULL;
    authorizer->matcher = spiffeid_MatchAny();

    return authorizer;
}

tlsconfig_Authorizer *tlsconfig_AuthorizeID(const spiffeid_ID id)
{
    tlsconfig_Authorizer *authorizer = malloc(sizeof *authorizer);

    authorizer->certified_chains = NULL;
    authorizer->matcher = spiffeid_MatchID(id);

    return authorizer;
}

tlsconfig_Authorizer *tlsconfig_AuthorizeOneOf(int n_args, ...)
{
    va_list args;
    va_start(args, n_args);

    tlsconfig_Authorizer *authorizer = malloc(sizeof *authorizer);
    authorizer->certified_chains = NULL;
    authorizer->matcher = spiffeid_vMatchOneOf(n_args, args);

    va_end(args);
    return authorizer;
}

tlsconfig_Authorizer *
tlsconfig_AuthorizeMemberOf(const spiffeid_TrustDomain td)
{
    tlsconfig_Authorizer *authorizer = malloc(sizeof *authorizer);

    authorizer->certified_chains = NULL;
    authorizer->matcher = spiffeid_MatchMemberOf(td);

    return authorizer;
}

void tlsconfig_Authorizer_Free(tlsconfig_Authorizer *authorizer)
{
    if(authorizer) {
        spiffeid_Matcher_Free(authorizer->matcher);

        /* authorizer does not own the certified chain. There is no need to
         * free it here */

        free(authorizer);
    }
}
