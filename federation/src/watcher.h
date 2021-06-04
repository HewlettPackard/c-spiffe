#ifndef INCLUDE_SPIFFEBUNDLE_WATCHER_H
#define INCLUDE_SPIFFEBUNDLE_WATCHER_H
#include "bundle/spiffebundle/src/bundle.h"
#include "bundle/spiffebundle/src/set.h"
#include "bundle/spiffebundle/src/source.h"
#include "endpoint.h"
#include "spiffeid/src/id.h"
#include "spiffeid/src/trustdomain.h"
#include "utils/src/util.h"
#include <curl/curl.h>
#include <uriparser/Uri.h>
#include <threads.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct spiffebundle_Endpoint_Status{
    spiffebundle_Endpoint *endpoint;
    cnd_t *cond_var;
    thrd_t *thread;
    int running;
} spiffebundle_Endpoint_Status;

typedef struct map_TD_Endpoint_Status {
    string_t key;
    spiffebundle_Endpoint_Status* value;
} map_TD_Endpoint_Status;

typedef struct spiffebundle_Watcher {
    map_TD_Endpoint_Status *endpoints;
} spiffebundle_Watcher;

spiffebundle_Watcher *spiffebundle_Watcher_New();
void spiffebundle_Watcher_Free(spiffebundle_Watcher *watcher);

err_t spiffebundle_Watcher_AddHttpsWebEndpoint(
    spiffebundle_Watcher *watcher, const char *url,
    spiffeid_TrustDomain trust_domain);

err_t spiffebundle_Watcher_AddHttpsSpiffeEndpoint(
    spiffebundle_Watcher *watcher, const char *url,
    spiffeid_TrustDomain trust_domain, const char* spiffeid,
    spiffebundle_Source *source);

err_t spiffebundle_Watcher_RemoveEndpoint(spiffebundle_Watcher *watcher, spiffeid_TrustDomain trust_domain);

err_t spiffebundle_Watcher_Start(spiffebundle_Watcher *watcher);

err_t spiffebundle_Watcher_Stop(spiffebundle_Watcher *watcher);

spiffebundle_Bundle *
spiffebundle_Watcher_GetBundleForTrustDomain(spiffebundle_Watcher *watcher,
                                             const spiffeid_TrustDomain td,
                                             err_t *err);

#ifdef __cplusplus
}
#endif

#endif // INCLUDE_SPIFFEBUNDLE_WATCHER_H
