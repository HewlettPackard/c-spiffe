#ifndef WATCHER_H
#define WATCHER_H

#include "../../svid/x509svid/src/svid.h"
#include "../../bundle/x509bundle/src/bundle.h"
#include "../../bundle/x509bundle/src/set.h"

#include "../../bundle/jwtbundle/src/bundle.h"
#include "../../bundle/jwtbundle/src/set.h"

#include <threads.h>


///TODO: function for picking first SVID
typedef struct workloadapi_X509Context
{
    x509svid_SVID** SVIDs;
    x509bundle_Set* Bundles;

} workloadapi_X509Context;

typedef struct workloadapi_WatcherConfig
{
    ///TODO: add actual client type
    void* client;
    ///TODO: add actual client option type
    void** clientOptions;
} workloadapi_WatcherConfig;

// type for callback function. will be set by X509Source.
typedef void (*workloadapi_x509ContextFunc_t)(workloadapi_X509Context*, void*); 
// eg.: 
// workloadapi_x509ContextFunc_t func; -> void (*func)(workloadapi_X509Context* updatedContext);

typedef struct X509Callback{
    void* args;
    workloadapi_x509ContextFunc_t func;
} workloadapi_X509Callback;

// typedef void(workloadapi_jwtBundleSetFunc_t)(jwtbundle_Set*);
// eg.: 


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

    workloadapi_X509Callback x509Callback; //function called with updated x509Context
    // jwtBundleSetFunc_t* jwtBundleSetUpdateFunc ; //function called with updated x509Context
    

} workloadapi_Watcher;

//new watcher, dials WorkloadAPI if client hasn't yet
workloadapi_Watcher* workloadapi_newWatcher(workloadapi_WatcherConfig config, workloadapi_X509Callback x509Callback/*, jwtBundleSetFunc_t* jwtBundleSetUpdateFunc*/, err_t* error);

//drops connection to WorkloadAPI (if watcher owns client)
err_t workloadapi_closeWatcher(workloadapi_Watcher* watcher);

//Function called by Client when new x509 response arrives
void workloadapi_Watcher_OnX509ContextUpdate(workloadapi_Watcher* watcher, workloadapi_X509Context* context);

//Called by Client when an error occurs and the watcher must be made aware
void workloadapi_Watcher_OnX509ContextWatchError(workloadapi_Watcher* watcher, err_t error);

// Function called by Client when new JWT response arrives
// void workloadapi_Watcher_OnJwtBundlesUpdate(workloadapi_Watcher* watcher, jwtbundle_Set* context);
// void workloadapi_Watcher_OnJwtBundlesWatchError(workloadapi_Watcher* watcher, err_t error);

// Blocks until an update is received.
err_t workloadapi_Watcher_WaitUntilUpdated(workloadapi_Watcher* watcher);

// Broadcasts an update to all waiting.
err_t workloadapi_Watcher_TriggerUpdated(workloadapi_Watcher* watcher);

// void* workloadapi_Watcher_Updated(workloadapi_Watcher* watcher);
// err_t workloadapi_Watcher_DrainUpdated(workloadapi_Watcher* watch);



#endif //WATCHER_H