
#include "watcher.h"

// int workloadapi_Watcher_BackgroundFunc(void * args){

// } 



//new watcher, dials WorkloadAPI if client hasn't yet
workloadapi_Watcher* workloadapi_newWatcher(/*context,*/ workloadapi_WatcherConfig config, workloadapi_X509Callback x509Callback/*, jwtBundleSetFunc_t* jwtBundleSetUpdateFunc*/){
    workloadapi_Watcher* newW = (workloadapi_Watcher*) calloc(1,sizeof *newW);
    if(config.client){
        newW->client = config.client;
        newW->ownsClient = false;
    }
    else{
        //create client
    }
    // set to 0 on calloc:
    // newW->closed = false;
    // newW->closeError =;

    mtx_init(&(newW->closeMutex),mtx_plain);
    thrd_create(&(newW->watcherThread),NULL,newW);

    ///TODO: wait for first update??? cond variable on mutex???
    workloadapi_Watcher_WaitUntilUpdated(newW);
    return newW;
}

//drops connection to WorkloadAPI (if owns client)
void workloadapi_closeWatcher(/*context,*/ workloadapi_Watcher* watcher){
    mtx_lock(&(watcher->closeMutex));
    watcher->closed = true;
    ///TODO: check watcher->closeError?
    ///TODO: notify thread of closure;
    ///TODO: 
    mtx_unlock(&(watcher->closeMutex));
}

//Function called by Client when new x509 response arrives
void workloadapi_Watcher_OnX509ContextUpdate(workloadapi_Watcher* watcher, workloadapi_X509Context* context){
    void *args = watcher->x509Callback.args;
    watcher->x509Callback.func(context,args);
}

//Called by Client when an error occurs
void workloadapi_Watcher_OnX509ContextWatchError(workloadapi_Watcher* watcher, err_t error){
    ///TODO: catch/recover/exit from error 
}
