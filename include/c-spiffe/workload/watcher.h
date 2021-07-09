#ifndef INCLUDE_WORKLOAD_WATCHER_H
#define INCLUDE_WORKLOAD_WATCHER_H

#include "c-spiffe/workload/client.h"
#include "c-spiffe/workload/x509context.h"
#include <threads.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct workloadapi_Client workloadapi_Client;
typedef void (*workloadapi_ClientOption)(workloadapi_Client *, void *);
typedef struct {
    workloadapi_Client *client;
    workloadapi_ClientOption *client_options;
} workloadapi_WatcherConfig;

typedef struct workloadapi_Watcher {
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

    /** function called with updated x509Context */
    workloadapi_X509Callback x509callback;

} workloadapi_Watcher;

/** creates and sets up a new watcher, doesn't dial client yet. */
workloadapi_Watcher *
workloadapi_newWatcher(workloadapi_WatcherConfig config,
                       workloadapi_X509Callback x509callback, err_t *error);

/** starts watcher thread and blocks until updated. dials client if needed. */
err_t workloadapi_Watcher_Start(workloadapi_Watcher *watcher);

/** drops connection to WorkloadAPI, and kills client (if watcher owns client)
 */
err_t workloadapi_Watcher_Close(workloadapi_Watcher *watcher);

/** frees watcher object. should be closed first. also frees client, if owned.
 */
err_t workloadapi_Watcher_Free(workloadapi_Watcher *watcher);

/** Function called by Client when new x509 response arrives. */
void workloadapi_Watcher_OnX509ContextUpdate(workloadapi_Watcher *watcher,
                                             workloadapi_X509Context *context);

/** Called by Client when an x509 error occurs and the watcher must be made
 * aware */
void workloadapi_Watcher_OnX509ContextWatchError(workloadapi_Watcher *watcher,
                                                 err_t error);

/** Blocks until an update is received. */
err_t workloadapi_Watcher_WaitUntilUpdated(workloadapi_Watcher *watcher);
err_t workloadapi_Watcher_TimedWaitUntilUpdated(workloadapi_Watcher *watcher,
                                                const struct timespec *timer);
/** Broadcasts an update to all waiting. */
err_t workloadapi_Watcher_TriggerUpdated(workloadapi_Watcher *watcher);

#ifdef __cplusplus
}
#endif

#endif // INCLUDE_WORKLOAD_WATCHER_H
