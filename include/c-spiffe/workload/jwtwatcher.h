#ifndef INCLUDE_WORKLOAD_JWTWATCHER_H
#define INCLUDE_WORKLOAD_JWTWATCHER_H

#include "c-spiffe/bundle/jwtbundle/set.h"
#include "c-spiffe/workload/client.h"
#include "c-spiffe/workload/jwtcallback.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct workloadapi_Client workloadapi_Client;
typedef void (*workloadapi_ClientOption)(workloadapi_Client *, void *);
typedef struct {
    workloadapi_Client *client;
    workloadapi_ClientOption *client_options;
} workloadapi_JWTWatcherConfig;

typedef struct workloadapi_JWTWatcher {
    /** Workload API client */
    workloadapi_Client *client;

    /** did this create its client? */
    bool owns_client;

    /** Update Sync */
    mtx_t update_mutex;
    cnd_t update_cond;
    bool updated;

    err_t update_error;

    /** Close sync */
    mtx_t close_mutex;
    bool closed;
    err_t close_error;

    /** thread spun to wait on updates */
    thrd_t watcher_thread;
    int thread_error;

    // function called with updated JWTBundleSet
    workloadapi_JWTCallback jwt_callback;

} workloadapi_JWTWatcher;

/** creates and sets up a new watcher, doesn't dial client yet. */
workloadapi_JWTWatcher *
workloadapi_newJWTWatcher(workloadapi_JWTWatcherConfig config,
                          workloadapi_JWTCallback jwt_callback, err_t *error);

/** starts watcher thread and blocks until updated. dials client if needed.
 */
err_t workloadapi_JWTWatcher_Start(workloadapi_JWTWatcher *watcher);

/** drops connection to WorkloadAPI, and kills client (if watcher owns
 * client) */
err_t workloadapi_JWTWatcher_Close(workloadapi_JWTWatcher *watcher);

/** frees watcher object. should be closed first. also frees client, if
 * owned. */
err_t workloadapi_JWTWatcher_Free(workloadapi_JWTWatcher *watcher);

// Function called by Client when new JWT response arrives
void workloadapi_JWTWatcher_OnJWTBundlesUpdate(workloadapi_JWTWatcher *watcher,
                                               jwtbundle_Set *context);
/** Called by Client when an JWT error occurs and the watcher must be made
 * aware */
void workloadapi_JWTWatcher_OnJWTBundlesWatchError(
    workloadapi_JWTWatcher *watcher, err_t error);

/** Blocks until an update is received. */
err_t workloadapi_JWTWatcher_WaitUntilUpdated(workloadapi_JWTWatcher *watcher);
err_t workloadapi_JWTWatcher_TimedWaitUntilUpdated(
    workloadapi_JWTWatcher *watcher, const struct timespec *timer);
/** Broadcasts an update to all waiting. */
err_t workloadapi_JWTWatcher_TriggerUpdated(workloadapi_JWTWatcher *watcher);

#ifdef __cplusplus
}
#endif

#endif // INCLUDE_WORKLOAD_JWTWATCHER_H
