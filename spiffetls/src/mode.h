#ifndef INCLUDE_SPIFFETLS_MODE_H
#define INCLUDE_SPIFFETLS_MODE_H

#include "../../bundle/x509bundle/src/source.h"
#include "../../internal/x509util/src/certpool.h"
#include "../../svid/x509svid/src/source.h"
#include "../../svid/x509svid/src/svid.h"
#include "../../workload/src/x509source.h"
#include "../tlsconfig/src/authorizer.h"

typedef enum {
    TLS_CLIENT_MODE,
    MTLS_CLIENT_MODE,
    MTLS_WEBCLIENT_MODE
} spiffetls_clientMode;

typedef enum {
    TLS_SERVER_MODE,
    MTLS_SERVER_MODE,
    MTLS_WEBSERVER_MODE
} spiffetls_serverMode;

typedef struct {
    spiffetls_clientMode mode;

    bool unneeded_source;

    tlsconfig_Authorizer *authorizer;

    workloadapi_X509Source *source;
    /// TODO: add X509 source options

    x509bundle_Source *bundle;
    x509svid_Source *svid;

    x509util_CertPool *roots;
} spiffetls_DialMode;

spiffetls_DialMode *spiffetls_TLSClient(tlsconfig_Authorizer *authorizer);
spiffetls_DialMode *
spiffetls_TLSClientWithSource(tlsconfig_Authorizer *authorizer,
                              workloadapi_X509Source *source);
spiffetls_DialMode *
spiffetls_TLSClientWithRawConfig(tlsconfig_Authorizer *authorizer,
                                 x509bundle_Source *bundle);
spiffetls_DialMode *spiffetls_MTLSClient(tlsconfig_Authorizer *authorizer);
spiffetls_DialMode *
spiffetls_MTLSClientWithSource(tlsconfig_Authorizer *authorizer,
                               workloadapi_X509Source *source);
spiffetls_DialMode *
spiffetls_MTLSClientWithRawConfig(tlsconfig_Authorizer *authorizer,
                                  x509bundle_Source *bundle,
                                  x509svid_Source *svid);
spiffetls_DialMode *spiffetls_MTLSWebClient(x509util_CertPool *roots);
spiffetls_DialMode *
spiffetls_MTLSWebClientWithSource(x509util_CertPool *roots,
                                  workloadapi_X509Source *source);
spiffetls_DialMode *
spiffetls_MTLSWebClientWithRawConfig(x509util_CertPool *roots,
                                     x509svid_Source *svid);

void spiffetls_DialMode_Free(spiffetls_DialMode *mode);

#endif // INCLUDE_SPIFFETLS_MODE_H
