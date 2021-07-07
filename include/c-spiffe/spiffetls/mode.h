#ifndef INCLUDE_SPIFFETLS_MODE_H
#define INCLUDE_SPIFFETLS_MODE_H

#include "c-spiffe/bundle/x509bundle/source.h"
#include "c-spiffe/internal/x509util/certpool.h"
#include "c-spiffe/spiffetls/tlsconfig/authorizer.h"
#include "c-spiffe/svid/x509svid/source.h"
#include "c-spiffe/workload/x509source.h"

#ifdef __cplusplus
extern "C" {
#endif

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

    x509bundle_Source *bundle;
    x509svid_Source *svid;

    x509util_CertPool *roots;
} spiffetls_DialMode;

typedef struct {
    spiffetls_serverMode mode;

    bool unneeded_source;

    tlsconfig_Authorizer *authorizer;

    workloadapi_X509Source *source;

    x509bundle_Source *bundle;
    x509svid_Source *svid;
} spiffetls_ListenMode;

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

spiffetls_ListenMode *spiffetls_TLSServer();
spiffetls_ListenMode *
spiffetls_TLSServerWithSource(workloadapi_X509Source *source);
spiffetls_ListenMode *spiffetls_TLSServerWithRawConfig(x509svid_Source *svid);
spiffetls_ListenMode *spiffetls_MTLSServer(tlsconfig_Authorizer *authorizer);
spiffetls_ListenMode *
spiffetls_MTLSServerWithSource(tlsconfig_Authorizer *authorizer,
                               workloadapi_X509Source *source);
spiffetls_ListenMode *
spiffetls_MTLSServerWithRawConfig(tlsconfig_Authorizer *authorizer,
                                  x509svid_Source *svid,
                                  x509bundle_Source *bundle);

void spiffetls_ListenMode_Free(spiffetls_ListenMode *mode);

#ifdef __cplusplus
}
#endif

#endif // INCLUDE_SPIFFETLS_MODE_H
