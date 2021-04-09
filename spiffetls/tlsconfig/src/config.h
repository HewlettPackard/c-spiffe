#ifndef INCLUDE_SPIFFETLS_TLSCONFIG_CONFIG_H
#define INCLUDE_SPIFFETLS_TLSCONFIG_CONFIG_H

#include "bundle/x509bundle/src/source.h"
#include "spiffetls/tlsconfig/src/authorizer.h"
#include "svid/x509svid/src/source.h"
#include <openssl/ssl.h>

typedef struct {
    void *trace;
    // tlsconfig_Trace *trace;
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

// tlsconfig_Option *tlsconfig_WithTrace(const tlsconfig_Trace *trace);

// SSL_CTX *tlsconfig_TLSClientConfig();
bool tlsconfig_HookTLSClientConfig(SSL_CTX *ctx, x509bundle_Source *bundle,
                                   tlsconfig_Authorizer *authorizer,
                                   tlsconfig_Option **opts);
// tlsconfig_MTLSClientConfig();
bool tlsconfig_HookMTLSClientConfig(SSL_CTX *ctx, x509svid_Source *svid,
                                    x509bundle_Source *bundle,
                                    tlsconfig_Authorizer *authorizer,
                                    tlsconfig_Option **opts);
// tlsconfig_MTLSWebClientConfig();
// void tlsconfig_HookMTLSWebClientConfig();
// tlsconfig_TLSServerConfig();
// tlsconfig_HookTLSServerConfig();
// tlsconfig_MTLSServerConfig();
// tlsconfig_HookMTLSServerConfig();
// tlsconfig_MTLSWebServerConfig();
// tlsconfig_HookMTLSWebServerConfig();
// tlsconfig_getTLSCertificate();
void tlsconfig_resetAuthFields(SSL_CTX *ctx);

void tlsconfig_Option_Free(tlsconfig_Option *option);

#endif // INCLUDE_SPIFFETLS_TLSCONFIG_CONFIG_H
