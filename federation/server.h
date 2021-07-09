#ifndef INCLUDE_FEDERATION_SERVER_H
#define INCLUDE_FEDERATION_SERVER_H

#include "bundle/spiffebundle.h"
#include "endpoint.h"
#include "spiffeid/spiffeid.h"
#include "spiffetls/spiffetls.h"
#include "svid/x509svid.h"
#include "utils/util.h"
#include <curl/curl.h>
#include <openssl/x509.h>
#include <threads.h>
#include <uriparser/Uri.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct spiffebundle_EndpointServer spiffebundle_EndpointServer;

uint SPIFFE_DEFAULT_HTTPS_PORT = 443;

typedef struct spiffebundle_EndpointServer_EndpointInfo {
    spiffebundle_EndpointServer *server;
    thrd_t thread;
    spiffetls_ListenMode *listen_mode;
    string_t url;
    uint port;
    bool active;
    mtx_t mutex;
} spiffebundle_EndpointServer_EndpointInfo;

spiffebundle_EndpointServer_EndpointInfo *
spiffebundle_EndpointServer_EndpointInfo_New();

err_t spiffebundle_EndpointServer_EndpointInfo_Free(
    spiffebundle_EndpointServer_EndpointInfo *e_info);

typedef struct map_string_endpoint_info {
    string_t key;
    spiffebundle_EndpointServer_EndpointInfo *value;
} map_string_endpoint_info;

typedef struct map_string_spiffebundle_Source {
    string_t key;
    spiffebundle_Source *value;
} map_string_spiffebundle_Source;

typedef struct spiffebundle_EndpointServer {
    map_string_spiffebundle_Source *bundle_sources;
    map_string_string *bundle_tds;
    map_string_endpoint_info *endpoints;
    mtx_t mutex;
} spiffebundle_EndpointServer;

// allocates server
spiffebundle_EndpointServer *spiffebundle_EndpointServer_New();
// frees server
err_t spiffebundle_EndpointServer_Free(spiffebundle_EndpointServer *server);

// adds bundle source to server, will be served at path.
err_t spiffebundle_EndpointServer_RegisterBundle(
    spiffebundle_EndpointServer *server, const char *path,
    spiffebundle_Source *bundle_source, spiffeid_TrustDomain td);

// updates bundle source.
err_t spiffebundle_EndpointServer_UpdateBundle(
    spiffebundle_EndpointServer *server, const char *path,
    spiffebundle_Source *new_source, spiffeid_TrustDomain td);

// removes bundle from server.
err_t spiffebundle_EndpointServer_RemoveBundle(
    spiffebundle_EndpointServer *server, const char *path);

// load keys to use with 'https_web'
// register a HTTPS_WEB endpoint, for starting with
// spiffebundle_EndpointServer_ServeEndpoint
spiffebundle_EndpointServer_EndpointInfo *
spiffebundle_EndpointServer_AddHttpsWebEndpoint(
    spiffebundle_EndpointServer *server, const char *base_url, X509 **cert,
    EVP_PKEY *priv_key, err_t *error);

err_t spiffebundle_EndpointServer_SetHttpsWebEndpointAuth(
    spiffebundle_EndpointServer *server, const char *base_url, X509 **cert,
    EVP_PKEY *priv_key);

// Register a HTTPS_SPIFFE endpoint, for starting with
// spiffebundle_EndpointServer_ServeEndpoint.
spiffebundle_EndpointServer_EndpointInfo *
spiffebundle_EndpointServer_AddHttpsSpiffeEndpoint(
    spiffebundle_EndpointServer *server, const char *base_url,
    x509svid_Source *svid_source, err_t *error);

err_t spiffebundle_EndpointServer_SetHttpsSpiffeEndpointSource(
    spiffebundle_EndpointServer *server, const char *base_url,
    x509svid_Source *svid_source);

// Get info for serving thread.
spiffebundle_EndpointServer_EndpointInfo *
spiffebundle_EndpointServer_GetEndpointInfo(
    spiffebundle_EndpointServer *server, const char *base_url, err_t *error);

// Remove endpoint from server.
err_t spiffebundle_EndpointServer_RemoveEndpoint(
    spiffebundle_EndpointServer *server, const char *base_url);

// Serve bundles using the set up protocol. Spawns a thread.
err_t spiffebundle_EndpointServer_ServeEndpoint(
    spiffebundle_EndpointServer *server, const char *base_url, uint port);

// Stop serving from indicated thread.
err_t spiffebundle_EndpointServer_StopEndpoint(
    spiffebundle_EndpointServer *server, const char *base_url);

// Stops serving from all threads.
err_t spiffebundle_EndpointServer_StopAll(spiffebundle_EndpointServer *server);

#ifdef __cplusplus
}
#endif

#endif // INCLUDE_FEDERATION_SERVER_H