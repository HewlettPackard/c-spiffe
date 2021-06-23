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
