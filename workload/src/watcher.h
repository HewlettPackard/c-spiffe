#ifndef WATCHER_H
#define WATCHER_H

#include "../../svid/x509svid/src/svid.h"
#include "../../bundle/x509bundle/src/bundle.h"
#include "../../bundle/x509bundle/src/set.h"

#include "../../bundle/jwtbundle/src/bundle.h"
#include "../../bundle/jwtbundle/src/set.h"

#include <threads.h>


//TODO function for picking first SVID
typedef struct workloadapi_X509Context
{
    x509svid_SVID** SVIDs;
    x509bundle_Set* Bundles;

} workloadapi_X509Context;

typedef struct workloadapi_WatcherConfig
{
    void* client; //TODO add actual client type
    void** clientOptions; //TODO add actual option type
    size_t options_size;
} workloadapi_WatcherConfig;

typedef void (*workloadapi_x509ContextFunc_t)(workloadapi_X509Context*, void*);  

typedef struct X509Callback{
    void* args;
    workloadapi_x509ContextFunc_t func;
} workloadapi_X509Callback;

// typedef void(workloadapi_jwtBundleSetFunc_t)(jwtbundle_Set*);
// function types eg. 
// workloadapi_x509ContextFunc_t func;  =  void func(workloadapi_X509Context* updatedContext);


typedef struct workloadapi_Watcher
{
    void* client; //TODO as above, pointer to Client C++ class;
    bool ownsClient; //did this create its client?

    // void(*cancel)(void); //cancel function, might not apply to our C impl

    //TODO sync objects?
    mtx_t closeMutex;
    bool closed;
    err_t closeError; //needed?
    
    thrd_t watcherThread; //thread spun to wait on updates

    workloadapi_X509Callback x509Callback; //function called with updated x509Context
    // jwtBundleSetFunc_t* jwtBundleSetUpdateFunc ; //function called with updated x509Context
    

} workloadapi_Watcher;

//new watcher, dials WorkloadAPI if client hasn't yet
workloadapi_Watcher* workloadapi_newWatcher(/*context,*/ workloadapi_WatcherConfig config, workloadapi_X509Callback x509Callback/*, jwtBundleSetFunc_t* jwtBundleSetUpdateFunc*/);

//drops connection to WorkloadAPI (if owns client)
void workloadapi_closeWatcher(/*context,*/ workloadapi_Watcher* watcher);

//Function called by Client when new x509 response arrives
void workloadapi_Watcher_OnX509ContextUpdate(workloadapi_Watcher* watcher, workloadapi_X509Context* context);
//Called by Client when an error occurs
void workloadapi_Watcher_OnX509ContextWatchError(workloadapi_Watcher* watcher, err_t error);

// Function called by Client when new JWT response arrives
// void workloadapi_Watcher_OnJwtBundlesUpdate(workloadapi_Watcher* watcher, jwtbundle_Set* context);
// void workloadapi_Watcher_OnJwtBundlesWatchError(workloadapi_Watcher* watcher, err_t error);

// TODO sync functions
err_t workloadapi_Watcher_WaitUntilUpdated(workloadapi_Watcher* watcher/*, go channel context*/);
// void* workloadapi_Watcher_Updated(workloadapi_Watcher* watcher); //TODO how to get updated without channels
// err_t workloadapi_Watcher_DrainUpdated(workloadapi_Watcher* watch); //
// err_t workloadapi_Watcher_TriggerUpdated(/* go channel context*/);



#endif //WATCHER_H