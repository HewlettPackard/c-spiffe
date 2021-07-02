#ifndef INCLUDE_SPIFFETLS_TLSCONFIG_CONFIG_H
#define INCLUDE_SPIFFETLS_TLSCONFIG_CONFIG_H

#include "c-spiffe/bundle/x509bundle/source.h"
#include "c-spiffe/spiffetls/tlsconfig/authorizer.h"
#include "c-spiffe/svid/x509svid/source.h"
#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void *trace;
} tlsconfig_options;

typedef void (*tlsconfig_option)(tlsconfig_options *);

typedef struct {
    enum { TLSCONFIG_FUNC /*, TLSCONFIG_OPTIONS*/ } type;
    union {
        /* tlsconfig_options *options;*/
        tlsconfig_option func;
    } source;
} tlsconfig_Option;

void tlsconfig_Option_apply(tlsconfig_Option *, tlsconfig_options *options);
tlsconfig_Option *tlsconfig_OptionFromFunc(tlsconfig_option fn);
tlsconfig_options *tlsconfig_newOptions(tlsconfig_Option **opts);

bool tlsconfig_HookTLSClientConfig(SSL_CTX *ctx, x509bundle_Source *bundle,
                                   tlsconfig_Authorizer *authorizer,
                                   tlsconfig_Option **opts);
bool tlsconfig_HookMTLSClientConfig(SSL_CTX *ctx, x509svid_Source *svid,
                                    x509bundle_Source *bundle,
                                    tlsconfig_Authorizer *authorizer,
                                    tlsconfig_Option **opts);
bool tlsconfig_HookTLSServerConfig(SSL_CTX *ctx, x509svid_Source *svid,
                                   tlsconfig_Option **opts);
bool tlsconfig_HookMTLSServerConfig(SSL_CTX *ctx, x509svid_Source *svid,
                                    x509bundle_Source *bundle,
                                    tlsconfig_Authorizer *authorizer,
                                    tlsconfig_Option **opts);
void tlsconfig_resetAuthFields(SSL_CTX *ctx);

void tlsconfig_Option_Free(tlsconfig_Option *option);

#ifdef __cplusplus
}
#endif

#endif // INCLUDE_SPIFFETLS_TLSCONFIG_CONFIG_H
