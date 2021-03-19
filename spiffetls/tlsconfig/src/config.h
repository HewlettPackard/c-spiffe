#ifndef INCLUDE_SPIFFETLS_TLSCONFIG_CONFIG_H
#define INCLUDE_SPIFFETLS_TLSCONFIG_CONFIG_H

#include "../../../bundle/x509bundle/src/source.h"
#include "../../../svid/x509svid/src/source.h"
#include "trace.h"
#include <openssl/ssl.h>

typedef struct {
    tlsconfig_Trace trace;
} tlsconfig_options;

typedef void (*tlsconfig_option)(tlsconfig_options *);

typedef struct {
    enum { TLSCONFIG_FUNC/*, TLSCONFIG_OPTIONS*/ } type;
    union {
        /* tlsconfig_options *options;*/
        tlsconfig_option *func;
    } source;
} tlsconfig_Option;

void tlsconfig_Option_apply(tlsconfig_Option *, tlsconfig_options *options);

tlsconfig_options *tlsconfig_newOptions(tlsconfig_Option **opts);

tlsconfig_Option *tlsconfig_WithTrace(const tlsconfig_Trace *trace);

SSL *tlsconfig_TLSClientConfig();
void tlsconfig_HookTLSClientConfig();
tlsconfig_MTLSClientConfig();
tlsconfig_HookMTLSClientConfig();
tlsconfig_MTLSWebClientConfig();
tlsconfig_HookMTLSWebClientConfig();
tlsconfig_TLSServerConfig();
tlsconfig_HookTLSServerConfig();
tlsconfig_MTLSServerConfig();
tlsconfig_HookMTLSServerConfig();
tlsconfig_MTLSWebServerConfig();
tlsconfig_HookMTLSWebServerConfig();
tlsconfig_getTLSCertificate();
void tlsconfig_resetAuthFields();

#endif // INCLUDE_SPIFFETLS_TLSCONFIG_CONFIG_H