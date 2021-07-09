#ifndef INCLUDE_FEDERATION_SERVER_H
#define INCLUDE_FEDERATION_SERVER_H

#include "bundle/spiffebundle/bundle.h"
#include "bundle/spiffebundle/set.h"
#include "bundle/spiffebundle/source.h"
#include "endpoint.h"
#include "spiffeid/id.h"
#include "svid/x509svid/source.h"
#include "spiffeid/trustdomain.h"
#include "utils/util.h"
#include <curl/curl.h>
#include <threads.h>
#include <uriparser/Uri.h>
#include <openssl/x509.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct map_int_thread{
    int key;
    thrd_t value;
} map_int_thread;

typedef struct map_string_spiffebundle_Source {
    string_t key;
    spiffebundle_Source *value;
}map_string_spiffebundle_Source;

typedef struct spiffebundle_EndpointServer
{  
    map_string_spiffebundle_Source* bundle_sources;
    map_int_thread* serving_threads;
    x509svid_Source* svid_source;
    ///TODO: set of keys
    mtx_t mutex;
    
} spiffebundle_EndpointServer;

//allocates server
spiffebundle_EndpointServer* spiffebundle_EndpointServer_New();
//frees server
err_t spiffebundle_EndpointServer_Free(spiffebundle_EndpointServer *server);

//adds bundle source to server, will be served at path.
err_t spiffebundle_EndpointServer_RegisterBundle(spiffebundle_EndpointServer* server, const char* path, spiffebundle_Source* bundle_source);

//updates bundle source.
err_t spiffebundle_EndpointServer_UpdateBundle(spiffebundle_EndpointServer* server, const char* path, spiffebundle_Source* new_source);

//removes bundle from server.
err_t spiffebundle_EndpointServer_RemoveBundle(spiffebundle_EndpointServer* server, const char* path);

//load keys to use with 'https_spiffe'
err_t spiffebundle_EndpointServer_LoadKeys(spiffebundle_EndpointServer* server, const char* path);
//unload keys
err_t spiffebundle_EndpointServer_ClearKeys(spiffebundle_EndpointServer* server);

//register a X509 SVID source for use with 'https_web'
err_t spiffebundle_EndpointServer_RegisterSVIDSource(spiffebundle_EndpointServer* server, x509svid_Source* svid_source);

//remove SVID source.
err_t spiffebundle_EndpointServer_ClearSVIDSource(spiffebundle_EndpointServer* server);

//Serve bundles using the 'https_web' protocol. Spawns a thread. 
int spiffebundle_EndpointServer_ServeHTTPSWeb(spiffebundle_EndpointServer* server, const char* base_url, uint port, err_t* error);

//Serve bundles using the 'https_spiffe' protocol. Spawns a thread. Returns an id that can be used to stop this serving thread.
int spiffebundle_EndpointServer_ServeHTTPSSpiffe(spiffebundle_EndpointServer* server, const char* base_url, uint port, err_t* error);

//stops serving from indicated thread.
err_t spiffebundle_EndpointServer_Stop(spiffebundle_EndpointServer* server, int thread_key);

//stops serving from all threads.
err_t spiffebundle_EndpointServer_StopAll(spiffebundle_EndpointServer* server);

#ifdef __cplusplus
}
#endif

#endif // INCLUDE_FEDERATION_SERVER_H
