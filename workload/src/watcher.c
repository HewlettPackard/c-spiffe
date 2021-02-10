
#include "watcher.h"

//Function that will run on thread spun for watcher
int workloadapi_Watcher_X509backgroundFunc(void * _watcher){
    workloadapi_Watcher* watcher = (workloadapi_Watcher*) _watcher;

    err_t error = NO_ERROR;
    
    error = workloadapi_WatchX509Context(watcher->client,watcher); 

    return (int) error;
}

//new watcher, creates client if not provided.
workloadapi_Watcher* workloadapi_newWatcher(workloadapi_WatcherConfig config, workloadapi_X509Callback x509Callback/*, jwtBundleSetFunc_t* jwtBundleSetUpdateFunc*/, err_t* error){
    
    workloadapi_Watcher* newW = (workloadapi_Watcher*) calloc(1,sizeof *newW);
    
    // set by calloc:
    // newW->updated = false;
    // newW->closed = false;
    // newW->closeError = NO_ERROR;
    // newW->updateError = NO_ERROR;
    // newW->threadError = thrd_success;
    
    if(config.client){
        newW->client = config.client;
        newW->ownsClient = false;
        if(config.clientOptions){
            for (size_t i = 0; i < arrlen(config.clientOptions); i++)
            {
                workloadapi_applyClientOption(config.client,config.clientOptions[i]);
            }
            
        }
    }
    else{
        newW->client = workloadapi_NewClient(error);
        if(*error != NO_ERROR){
            free(newW);
            return NULL;
        }
        newW->ownsClient = true;
        if(config.clientOptions){
            for (size_t i = 0; i < arrlen(config.clientOptions); i++)
            {
                workloadapi_applyClientOption(newW->client,config.clientOptions[i]);
            }
            
        }
    }

    ///TODO: check if callback is valid?
    newW->x509Callback = x509Callback;

    int thread_error = mtx_init(&(newW->closeMutex),mtx_plain);
    if(thread_error != thrd_success){
        ///TODO: return thread error?
        *error =  ERROR2;
        return NULL;
    }
    thread_error = mtx_init(&(newW->updateMutex),mtx_plain);
    if(thread_error != thrd_success){
        ///TODO: return thread error?
        *error =  ERROR2;
        return NULL;
    }
    thread_error = cnd_init(&(newW->updateCond));
    if(thread_error != thrd_success){
        ///TODO: return thread error?
        *error =  ERROR2;
        return NULL;
    }

    return newW;
}

//starts watcher and blocks waiting on an update.
err_t workloadapi_startWatcher(workloadapi_Watcher* watcher){
    err_t error = NO_ERROR;
    if(!watcher){
        return ERROR1; /// NULL WATCHER;
    }
    /// spin watcher thread out.
    int thread_error = thrd_create(&(watcher->watcherThread),workloadapi_Watcher_X509backgroundFunc,watcher);
    
    if (thread_error != thrd_success){
        watcher->threadError = thread_error;
        return ERROR2; // THREAD ERROR, see watcher->threadERROR for error
    }

    ///wait for update and check for errors.
    error = workloadapi_Watcher_WaitUntilUpdated(watcher);
    if(error != NO_ERROR){
    ///TODO: add error handling and destroy thread. error is already set so we just need to get our bearings and deallocate stuff;
       watcher->updateError = error;
       return ERROR3;
    }
    return error;
}

//drops connection to WorkloadAPI (if owns client)
err_t workloadapi_closeWatcher(workloadapi_Watcher* watcher){
    mtx_lock(&(watcher->closeMutex));
    watcher->closed = true;
    err_t error = NO_ERROR;
    ///TODO: check and set watcher->closeError?
    if(watcher->ownsClient){
        error = workloadapi_CloseClient(watcher->client);
        if(error != NO_ERROR){
            mtx_unlock(&(watcher->closeMutex));
            return error;
        }
        error = workloadapi_FreeClient(watcher->client);
        if(error != NO_ERROR){
            //shouldn't reach here.
        }
    }
    mtx_unlock(&(watcher->closeMutex));
    int join_return;
    int thread_error = thrd_join(watcher->watcherThread,&join_return);
    if(thread_error == thrd_success){
        return join_return;
    } 
}

//drops connection to WorkloadAPI (if owns client) MUST ALREADY BE CLOSED.
err_t workloadapi_freeWatcher(/*context,*/ workloadapi_Watcher* watcher){
    ///TODO: free watcher 
    mtx_destroy(&(watcher->closeMutex));
    cnd_destroy(&(watcher->updateCond));
    mtx_destroy(&(watcher->updateMutex));
    if(watcher->ownsClient){
        ///TODO: call freeClient();
    }
    free(watcher);
    return NO_ERROR;
}

//Function called by Client when new x509 response arrives
void workloadapi_Watcher_OnX509ContextUpdate(workloadapi_Watcher* watcher, workloadapi_X509Context* context){
    void *args = watcher->x509Callback.args;
    watcher->x509Callback.func(context,args);
    workloadapi_Watcher_TriggerUpdated(watcher);
}

//Called by Client when an error occurs
void workloadapi_Watcher_OnX509ContextWatchError(workloadapi_Watcher* watcher, err_t error){
    ///TODO: catch/recover/exit from watch error 
    ///INFO: go-spiffe does nothing.
}


err_t workloadapi_Watcher_WaitUntilUpdated(workloadapi_Watcher* watcher){
    return workloadapi_Watcher_TimedWaitUntilUpdated(watcher,NULL);
}

err_t workloadapi_Watcher_TimedWaitUntilUpdated(workloadapi_Watcher* watcher, struct timespec *timer){
    mtx_lock(&watcher->updateMutex);
    if (watcher->updated){
        mtx_unlock(&watcher->updateMutex);
        return NO_ERROR;
    }
    else{
        int thread_error = thrd_success;
        if(timer != NULL){
            thread_error = cnd_timedwait(&(watcher->updateCond), &(watcher->updateMutex), timer);
            if (thread_error == thrd_timedout){
                mtx_unlock(&(watcher->updateMutex));
                return ERROR1;//timed out
            }
        }else{
            thread_error = cnd_wait(&(watcher->updateCond), &(watcher->updateMutex));
        }
        mtx_unlock(&watcher->updateMutex);
        if(thread_error != thrd_success){
            return ERROR2;
        }
        else{
            return NO_ERROR;
        }
    }
}

err_t workloadapi_Watcher_TriggerUpdated(workloadapi_Watcher* watcher){
    mtx_lock(&(watcher->updateMutex));
    watcher->updated = true;
    cnd_broadcast(&(watcher->updateCond));
    mtx_unlock(&(watcher->updateMutex));
    return NO_ERROR; ///TODO: error checking?
}
