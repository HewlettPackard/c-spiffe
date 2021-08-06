#ifndef INCLUDE_SPIFFETLS_TLSCONFIG_AUTHORIZER_H
#define INCLUDE_SPIFFETLS_TLSCONFIG_AUTHORIZER_H

#include "c-spiffe/spiffeid/match.h"
#include <openssl/x509.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tlsconfig_Authorizer {
    spiffeid_Matcher *matcher;
    // list of arrays of pointers to X509 certificates
    X509 ***certified_chains;
} tlsconfig_Authorizer;

tlsconfig_Authorizer *tlsconfig_AuthorizeAny(void);
tlsconfig_Authorizer *tlsconfig_AuthorizeID(const spiffeid_ID id);
tlsconfig_Authorizer *tlsconfig_AuthorizeOneOf(int n_args, ...);
tlsconfig_Authorizer *
tlsconfig_AuthorizeMemberOf(const spiffeid_TrustDomain td);

match_err_t tlsconfig_ApplyAuthorizer(tlsconfig_Authorizer *authorizer,
                                      const spiffeid_ID id, X509 ***certs);

void tlsconfig_Authorizer_Free(tlsconfig_Authorizer *authorizer);

#ifdef __cplusplus
}
#endif

#endif
