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
