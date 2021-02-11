#ifndef __INCLUDE_WORKLOAD_WATCHER_H__
#define __INCLUDE_WORKLOAD_WATCHER_H__

#include "x509context.h"
#include "client.h"
#include "../../svid/x509svid/src/svid.h"
#include "../../bundle/x509bundle/src/bundle.h"
#include "../../bundle/x509bundle/src/set.h"

#include "../../bundle/jwtbundle/src/bundle.h"
#include "../../bundle/jwtbundle/src/set.h"

#include <threads.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct workloadapi_Client workloadapi_Client;
typedef void (*workloadapi_ClientOption)(workloadapi_Client*,void*);
typedef struct workloadapi_WatcherConfig
{
    workloadapi_Client* client;
    workloadapi_ClientOption *clientOptions;
} workloadapi_WatcherConfig;

// typedef void(workloadapi_jwtBundleSetFunc_t)(jwtbundle_Set*);
// eg.: 

///TODO: define error codes.

typedef struct workloadapi_Watcher
{
    void* client; ///TODO: as above, pointer to Client C++ class;
    bool ownsClient; //did this create its client?

    //Update Sync
    mtx_t updateMutex;
    cnd_t updateCond;
    bool updated;
    
    ///TODO: needed?
    err_t updateError;


    //Close sync
    mtx_t closeMutex;
    bool closed;
    err_t closeError; //needed?
    
    thrd_t watcherThread; //thread spun to wait on updates
    int threadError;

    workloadapi_X509Callback x509Callback; //function called with updated x509Context
    // jwtBundleSetFunc_t* jwtBundleSetUpdateFunc ; //function called with updated x509Context
    

} workloadapi_Watcher;

// creates and sets up a new watcher, doesn't dial client yet.
workloadapi_Watcher* workloadapi_newWatcher(workloadapi_WatcherConfig config, workloadapi_X509Callback x509Callback/*, jwtBundleSetFunc_t* jwtBundleSetUpdateFunc*/, err_t* error);

//starts watcher thread and blocks until updated. dials client if needed.
err_t workloadapi_startWatcher(workloadapi_Watcher* watcher);

//drops connection to WorkloadAPI, and kills client (if watcher owns client)
err_t workloadapi_closeWatcher(workloadapi_Watcher* watcher);

// frees watcher object. should be closed first. also frees client, if owned.
err_t workloadapi_freeWatcher(workloadapi_Watcher* watcher);

//Function called by Client when new x509 response arrives.
void workloadapi_Watcher_OnX509ContextUpdate(workloadapi_Watcher* watcher, workloadapi_X509Context* context);

//Called by Client when an error occurs and the watcher must be made aware
void workloadapi_Watcher_OnX509ContextWatchError(workloadapi_Watcher* watcher, err_t error);

// Function called by Client when new JWT response arrives
// void workloadapi_Watcher_OnJwtBundlesUpdate(workloadapi_Watcher* watcher, jwtbundle_Set* context);
// void workloadapi_Watcher_OnJwtBundlesWatchError(workloadapi_Watcher* watcher, err_t error);

// Blocks until an update is received.
err_t workloadapi_Watcher_WaitUntilUpdated(workloadapi_Watcher* watcher);
err_t workloadapi_Watcher_TimedWaitUntilUpdated(workloadapi_Watcher* watcher, struct timespec * timer);
// Broadcasts an update to all waiting.
err_t workloadapi_Watcher_TriggerUpdated(workloadapi_Watcher* watcher);


#ifdef __cplusplus
}
#endif

#endif //__INCLUDE_WORKLOAD_WATCHER_H__