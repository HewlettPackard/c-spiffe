#include "spiffetls/tlsconfig/src/authorizer.h"

match_t tlsconfig_ApplyAuthorizer(tlsconfig_Authorizer *authorizer,
                                  const spiffeid_ID id,
                                  const X509 ***certified)
{
    authorizer->certifiedChains = certified;
    return spiffeid_ApplyMatcher(authorizer->matcher, id);
}

tlsconfig_Authorizer *tlsconfig_AuthourizeAny()
{
    tlsconfig_Authorizer *authorizer = malloc(sizeof *authorizer);

    authorizer->certifiedChains = NULL;
    authorizer->matcher = spiffeid_MatchAny();

    return authorizer;
}

tlsconfig_Authorizer *tlsconfig_AuthourizeID(const spiffeid_ID id)
{
    tlsconfig_Authorizer *authorizer = malloc(sizeof *authorizer);

    authorizer->certifiedChains = NULL;
    authorizer->matcher = spiffeid_MatchID(id);

    return authorizer;
}

tlsconfig_Authorizer *tlsconfig_AuthourizeOneOf(int n_args, ...)
{
    va_list args;
    va_start(args, n_args);

    tlsconfig_Authorizer *authorizer = malloc(sizeof *authorizer);
    authorizer->certifiedChains = NULL;
    authorizer->matcher = spiffeid_vMatchOneOf(n_args, args);

    va_end(args);
    return authorizer;
}

tlsconfig_Authorizer *
tlsconfig_AuthourizeMemberOf(const spiffeid_TrustDomain td)
{
    tlsconfig_Authorizer *authorizer = malloc(sizeof *authorizer);

    authorizer->certifiedChains = NULL;
    authorizer->matcher = spiffeid_MatchMemberOf(td);

    return authorizer;
}
