#ifndef __INCLUDE_SPIFFETLS_TLSCONFIG_AUTHORIZER_H__
#define __INCLUDE_SPIFFETLS_TLSCONFIG_AUTHORIZER_H__

#include "../../../spiffeid/src/match.h"
#include <openssl/x509.h>

typedef struct tlsconfig_Authorizer {
    spiffeid_Matcher *matcher;
    // list of arrays of pointers to X509 certificates
    X509 ***certifiedChains;
} tlsconfig_Authorizer;

tlsconfig_Authorizer *tlsconfig_AuthourizeAny(void);
tlsconfig_Authorizer *tlsconfig_AuthourizeID(const spiffeid_ID id);
tlsconfig_Authorizer *tlsconfig_AuthourizeOneOf(int n_args, ...);
tlsconfig_Authorizer *
tlsconfig_AuthourizeMemberOf(const spiffeid_TrustDomain td);

match_t tlsconfig_ApplyAuthorizer(tlsconfig_Authorizer *authorizer,
                                  const spiffeid_ID id, const X509 ***certs);

#endif