#ifndef WATCHER_H
#define WATCHER_H

#include "../../svid/x509svid/src/svid.h"
#include "../../bundle/x509bundle/src/bundle.h"
#include "../../bundle/x509bundle/src/set.h"

#include "../../bundle/jwtbundle/src/bundle.h"
#include "../../bundle/jwtbundle/src/set.h"

#include <threads.h>


//TODO function for picking first SVID
typedef struct X509Context
{
    x509svid_SVID** SVIDs;
    size_t len_svids;
    x509bundle_Set* Bundles;

} X509Context;

typedef struct WatcherConfig
{
    void* client; //TODO add actual client type
    void** clientOptions; //TODO add actual option type
    size_t options_size;
} WatcherConfig;

typedef void(x509ContextFunc_t)(X509Context*);
typedef void(jwtBundleSetFunc_t)(jwtbundle_Set*);

typedef struct Watcher
{
    void* client; //TODO as above, pointer to Client C++ class;
    bool ownsClient = false; //did this create its client?

    void(*cancel)(void); //cancel function, might not apply to our C impl

    //TODO sync objects?
    mtx_t closeMutex;
    bool closed;
    err_t closeError; //needed?
    
    thrd_t watcherThread; //thread spun to wait on updates 

    x509ContextFunc_t* x509ContextUpdateFunc; //function called with updated x509Context
    jwtBundleSetFunc_t* jwtBundleSetUpdateFunc ; //function called with updated x509Context
    

} Watcher;

//new watcher, dials WorkloadAPI if client hasn't yet
Watcher* newWatcher(/*context,*/ WatcherConfig config, x509ContextFunc_t* x509ContextUpdateFunc, jwtBundleSetFunc_t* jwtBundleSetUpdateFunc);

//drops connection to WorkloadAPI (if owns client)
void closeWatcher(/*context,*/ Watcher* watcher);

//Function called by Client when new x509 response arrives
void Watcher_OnX509ContextUpdate(Watcher* watcher, X509Context* context);
//Called by Client when an error occurs
void Watcher_OnX509ContextWatchError(Watcher* watcher, err_t error);

//Function called by Client when new JWT response arrives
void Watcher_OnJwtBundlesUpdate(Watcher* watcher, jwtbundle_Set* context);
void Watcher_OnJwtBundlesWatchError(Watcher* watcher, err_t error);


err_t Watcher_WaitUntilUpdated(Watcher* watcher/*, go channel context*/);
void* Watcher_Updated(Watcher* watcher); //TODO how to get updated without channels
err_t Watcher_DrainUpdated(Watcher* watch); //
err_t Watcher_TriggerUpdated(/* go channel context*/);



#endif //WATCHER_H