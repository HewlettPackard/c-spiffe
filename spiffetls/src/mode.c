#include "mode.h"

spiffetls_DialMode *spiffetls_TLSClient(tlsconfig_Authorizer *authorizer)
{
    spiffetls_DialMode *mode = malloc(sizeof *mode);
    memset(mode, 0, sizeof *mode);
    mode->mode = TLS_CLIENT_MODE;
    mode->authorizer = authorizer;

    return mode;
}

spiffetls_DialMode *
spiffetls_TLSClientWithSource(tlsconfig_Authorizer *authorizer,
                              workloadapi_X509Source *source)
{
    spiffetls_DialMode *mode = malloc(sizeof *mode);
    memset(mode, 0, sizeof *mode);
    mode->mode = TLS_CLIENT_MODE;
    mode->authorizer = authorizer;
    mode->source = source;

    return mode;
}

spiffetls_DialMode *
spiffetls_TLSClientWithRawConfig(tlsconfig_Authorizer *authorizer,
                                 x509bundle_Source *bundle)
{
    spiffetls_DialMode *mode = malloc(sizeof *mode);
    memset(mode, 0, sizeof *mode);
    mode->mode = TLS_CLIENT_MODE;
    mode->authorizer = authorizer;
    mode->unneeded_source = true;
    mode->bundle = bundle;

    return mode;
}

spiffetls_DialMode *spiffetls_MTLSClient(tlsconfig_Authorizer *authorizer)
{
    spiffetls_DialMode *mode = malloc(sizeof *mode);
    memset(mode, 0, sizeof *mode);
    mode->mode = MTLS_CLIENT_MODE;
    mode->authorizer = authorizer;

    return mode;
}

spiffetls_DialMode *
spiffetls_MTLSClientWithSource(tlsconfig_Authorizer *authorizer,
                               workloadapi_X509Source *source)
{
    spiffetls_DialMode *mode = malloc(sizeof *mode);
    memset(mode, 0, sizeof *mode);
    mode->mode = MTLS_CLIENT_MODE;
    mode->authorizer = authorizer;
    mode->source = source;

    return mode;
}

spiffetls_DialMode *
spiffetls_MTLSClientWithRawConfig(tlsconfig_Authorizer *authorizer,
                                  x509bundle_Source *bundle,
                                  x509svid_SVID *svid)
{
    spiffetls_DialMode *mode = malloc(sizeof *mode);
    memset(mode, 0, sizeof *mode);
    mode->mode = MTLS_CLIENT_MODE;
    mode->authorizer = authorizer;
    mode->unneeded_source = true;
    mode->bundle = bundle;
    mode->svid = svid;

    return mode;
}

spiffetls_DialMode *spiffetls_MTLSWebClient(x509util_CertPool *roots)
{
    spiffetls_DialMode *mode = malloc(sizeof *mode);
    memset(mode, 0, sizeof *mode);
    mode->mode = MTLS_WEBCLIENT_MODE;
    mode->roots = roots;

    return mode;
}

spiffetls_DialMode *
spiffetls_MTLSWebClientWithSource(x509util_CertPool *roots,
                                  workloadapi_X509Source *source)
{
    spiffetls_DialMode *mode = malloc(sizeof *mode);
    memset(mode, 0, sizeof *mode);
    mode->mode = MTLS_WEBCLIENT_MODE;
    mode->roots = roots;
    mode->source = source;

    return mode;
}

spiffetls_DialMode *
spiffetls_MTLSWebClientWithRawConfig(x509util_CertPool *roots,
                                     x509svid_SVID *svid)
{
    spiffetls_DialMode *mode = malloc(sizeof *mode);
    memset(mode, 0, sizeof *mode);
    mode->mode = MTLS_WEBCLIENT_MODE;
    mode->roots = roots;
    mode->unneeded_source = true;
    mode->svid = svid;

    return mode;
}