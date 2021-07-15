#ifndef INCLUDE_FEDERATION_SERVER_H
#define INCLUDE_FEDERATION_SERVER_H

#include "c-spiffe/bundle/spiffebundle.h"
#include "c-spiffe/federation/endpoint.h"
#include "c-spiffe/spiffeid/spiffeid.h"
#include "c-spiffe/spiffetls/spiffetls.h"
#include "c-spiffe/svid/x509svid.h"
#include "c-spiffe/utils/util.h"
#include <curl/curl.h>
#include <openssl/x509.h>
#include <threads.h>
#include <uriparser/Uri.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct spiffebundle_EndpointServer spiffebundle_EndpointServer;
typedef struct spiffebundle_EndpointInfo spiffebundle_EndpointInfo;

uint SPIFFE_DEFAULT_HTTPS_PORT = 443;

typedef struct spiffebundle_EndpointThread {
    spiffebundle_EndpointInfo *endpoint_info;
    thrd_t thread;
    uint port;
    int control_socks[2];
    spiffetls_listenConfig config;
    bool active;
} spiffebundle_EndpointThread;

typedef struct map_port_endpoint_thread {
    uint key;
    spiffebundle_EndpointThread *value;
} map_port_endpoint_thread;

typedef struct spiffebundle_EndpointInfo {
    spiffebundle_EndpointServer *server;
    string_t url;
    spiffetls_ListenMode *listen_mode;
    map_port_endpoint_thread *threads;
    mtx_t mutex;
} spiffebundle_EndpointInfo;

spiffebundle_EndpointInfo *spiffebundle_EndpointInfo_New();

err_t spiffebundle_EndpointInfo_Free(
    spiffebundle_EndpointInfo *e_info);

typedef struct map_string_endpoint_info {
    string_t key;
    spiffebundle_EndpointInfo *value;
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
spiffebundle_EndpointInfo *spiffebundle_EndpointServer_AddHttpsWebEndpoint(
    spiffebundle_EndpointServer *server, const char *base_url, X509 **cert,
    EVP_PKEY *priv_key, err_t *error);

err_t spiffebundle_EndpointServer_SetHttpsWebEndpointAuth(
    spiffebundle_EndpointServer *server, const char *base_url, X509 **cert,
    EVP_PKEY *priv_key);

// Register a HTTPS_SPIFFE endpoint, for starting with
// spiffebundle_EndpointServer_ServeEndpoint.
spiffebundle_EndpointInfo *spiffebundle_EndpointServer_AddHttpsSpiffeEndpoint(
    spiffebundle_EndpointServer *server, const char *base_url,
    x509svid_Source *svid_source, err_t *error);

err_t spiffebundle_EndpointServer_SetHttpsSpiffeEndpointSource(
    spiffebundle_EndpointServer *server, const char *base_url,
    x509svid_Source *svid_source);

// Get info for serving thread.
spiffebundle_EndpointInfo *spiffebundle_EndpointServer_GetEndpointInfo(
    spiffebundle_EndpointServer *server, const char *base_url, err_t *error);

// Remove endpoint from server.
err_t spiffebundle_EndpointServer_RemoveEndpoint(
    spiffebundle_EndpointServer *server, const char *base_url);

// Serve bundles using the set up protocol. Spawns a thread.
err_t spiffebundle_EndpointServer_ServeEndpoint(
    spiffebundle_EndpointServer *server, const char *base_url, uint port);

// Stop serving from indicated endpoint.
err_t spiffebundle_EndpointServer_StopEndpoint(
    spiffebundle_EndpointServer *server, const char *base_url);

// Stop serving from indicated thread.
err_t spiffebundle_EndpointServer_StopEndpointThread(
    spiffebundle_EndpointServer *server, const char *base_url, uint port);

// Stops serving from all endpoints.
err_t spiffebundle_EndpointServer_Stop(spiffebundle_EndpointServer *server);

#ifdef __cplusplus
}
#endif

#endif // INCLUDE_FEDERATION_SERVER_H
