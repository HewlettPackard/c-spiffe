#include "c-spiffe/spiffetls/mode.h"

static spiffetls_DialMode *malloc_dialmode(void)
{
    spiffetls_DialMode *mode = malloc(sizeof *mode);
    if(mode) {
        return mode;
    } else {
        exit(EXIT_FAILURE);
    }
}

static spiffetls_ListenMode *malloc_listenmode(void)
{
    spiffetls_ListenMode *mode = malloc(sizeof *mode);
    if(mode) {
        return mode;
    } else {
        exit(EXIT_FAILURE);
    }
}

spiffetls_DialMode *spiffetls_TLSClient(tlsconfig_Authorizer *authorizer)
{
    spiffetls_DialMode *mode = malloc_dialmode();
    memset(mode, 0, sizeof *mode);
    mode->mode = TLS_CLIENT_MODE;
    mode->authorizer = authorizer;

    return mode;
}

spiffetls_DialMode *
spiffetls_TLSClientWithSource(tlsconfig_Authorizer *authorizer,
                              workloadapi_X509Source *source)
{
    spiffetls_DialMode *mode = malloc_dialmode();
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
    spiffetls_DialMode *mode = malloc_dialmode();
    memset(mode, 0, sizeof *mode);
    mode->mode = TLS_CLIENT_MODE;
    mode->authorizer = authorizer;
    mode->unneeded_source = true;
    mode->bundle = bundle;

    return mode;
}

spiffetls_DialMode *spiffetls_MTLSClient(tlsconfig_Authorizer *authorizer)
{
    spiffetls_DialMode *mode = malloc_dialmode();
    memset(mode, 0, sizeof *mode);
    mode->mode = MTLS_CLIENT_MODE;
    mode->authorizer = authorizer;

    return mode;
}

spiffetls_DialMode *
spiffetls_MTLSClientWithSource(tlsconfig_Authorizer *authorizer,
                               workloadapi_X509Source *source)
{
    spiffetls_DialMode *mode = malloc_dialmode();
    memset(mode, 0, sizeof *mode);
    mode->mode = MTLS_CLIENT_MODE;
    mode->authorizer = authorizer;
    mode->source = source;

    return mode;
}

spiffetls_DialMode *
spiffetls_MTLSClientWithRawConfig(tlsconfig_Authorizer *authorizer,
                                  x509bundle_Source *bundle,
                                  x509svid_Source *svid)
{
    spiffetls_DialMode *mode = malloc_dialmode();
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
    spiffetls_DialMode *mode = malloc_dialmode();
    memset(mode, 0, sizeof *mode);
    mode->mode = MTLS_WEBCLIENT_MODE;
    mode->roots = roots;

    return mode;
}

spiffetls_DialMode *
spiffetls_MTLSWebClientWithSource(x509util_CertPool *roots,
                                  workloadapi_X509Source *source)
{
    spiffetls_DialMode *mode = malloc_dialmode();
    memset(mode, 0, sizeof *mode);
    mode->mode = MTLS_WEBCLIENT_MODE;
    mode->roots = roots;
    mode->source = source;

    return mode;
}

spiffetls_DialMode *
spiffetls_MTLSWebClientWithRawConfig(x509util_CertPool *roots,
                                     x509svid_Source *svid)
{
    spiffetls_DialMode *mode = malloc_dialmode();
    memset(mode, 0, sizeof *mode);
    mode->mode = MTLS_WEBCLIENT_MODE;
    mode->roots = roots;
    mode->unneeded_source = true;
    mode->svid = svid;

    return mode;
}

void spiffetls_DialMode_Free(spiffetls_DialMode *mode)
{
    if(mode) {
        tlsconfig_Authorizer_Free(mode->authorizer);
        x509util_CertPool_Free(mode->roots);
        workloadapi_X509Source *source
            = mode->bundle ? mode->bundle->source.source : NULL;
        x509bundle_Source_Free(mode->bundle);
        if(mode->svid) {
            workloadapi_X509Source *const tmp_source
                = mode->svid->source.source;
            if(tmp_source != source) {
                x509svid_Source_Free(mode->svid);
            } else {
                // source is already freed
                free(mode->svid);
            }
            source = tmp_source;
        }
        if(mode->source) {
            if(mode->source != source) {
                workloadapi_X509Source_Free(mode->source);
            }
        }

        free(mode);
    }
}

spiffetls_ListenMode *spiffetls_TLSServer()
{
    spiffetls_ListenMode *mode = malloc_listenmode();
    memset(mode, 0, sizeof *mode);
    mode->mode = TLS_SERVER_MODE;

    return mode;
}

spiffetls_ListenMode *
spiffetls_TLSServerWithSource(workloadapi_X509Source *source)
{
    spiffetls_ListenMode *mode = malloc_listenmode();
    memset(mode, 0, sizeof *mode);
    mode->mode = TLS_SERVER_MODE;
    mode->source = source;

    return mode;
}

spiffetls_ListenMode *spiffetls_TLSServerWithRawConfig(x509svid_Source *svid)
{
    spiffetls_ListenMode *mode = malloc_listenmode();
    memset(mode, 0, sizeof *mode);
    mode->mode = TLS_SERVER_MODE;
    mode->unneeded_source = true;
    mode->svid = svid;

    return mode;
}

spiffetls_ListenMode *spiffetls_MTLSServer(tlsconfig_Authorizer *authorizer)
{
    spiffetls_ListenMode *mode = malloc_listenmode();
    memset(mode, 0, sizeof *mode);
    mode->mode = MTLS_SERVER_MODE;
    mode->authorizer = authorizer;

    return mode;
}

spiffetls_ListenMode *
spiffetls_MTLSServerWithSource(tlsconfig_Authorizer *authorizer,
                               workloadapi_X509Source *source)
{
    spiffetls_ListenMode *mode = malloc_listenmode();
    memset(mode, 0, sizeof *mode);
    mode->mode = MTLS_SERVER_MODE;
    mode->authorizer = authorizer;
    mode->source = source;

    return mode;
}

spiffetls_ListenMode *
spiffetls_MTLSServerWithRawConfig(tlsconfig_Authorizer *authorizer,
                                  x509svid_Source *svid,
                                  x509bundle_Source *bundle)
{
    spiffetls_ListenMode *mode = malloc_listenmode();
    memset(mode, 0, sizeof *mode);
    mode->mode = MTLS_SERVER_MODE;
    mode->unneeded_source = true;
    mode->authorizer = authorizer;
    mode->svid = svid;
    mode->bundle = bundle;

    return mode;
}

void spiffetls_ListenMode_Free(spiffetls_ListenMode *mode)
{
    if(mode) {
        tlsconfig_Authorizer_Free(mode->authorizer);
        workloadapi_X509Source *source
            = mode->bundle ? mode->bundle->source.source : NULL;
        x509bundle_Source_Free(mode->bundle);
        if(mode->svid) {
            workloadapi_X509Source *const tmp_source
                = mode->svid->source.source;
            if(tmp_source != source) {
                x509svid_Source_Free(mode->svid);
            } else {
                // source is already freed
                free(mode->svid);
            }
            source = tmp_source;
        }
        if(mode->source) {
            if(mode->source != source) {
                workloadapi_X509Source_Free(mode->source);
            }
        }

        free(mode);
    }
}
