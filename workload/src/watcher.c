#include "watcher.h"
#include "client.h"
#include "x509context.h"
#include "x509source.h"

// Function that will run on thread spun for watcher
int workloadapi_Watcher_X509backgroundFunc(void *_watcher)
{
    workloadapi_Watcher *watcher = (workloadapi_Watcher *) _watcher;

    err_t error = NO_ERROR;
    // TODO: CHECK ERROR AND RETRY
    do {
        error = workloadapi_Client_WatchX509Context(watcher->client, watcher);
    } while(error != ERROR5); // error5 == client closed
    return (int) error;
}

// new watcher, creates client if not provided.
workloadapi_Watcher *workloadapi_newWatcher(
    workloadapi_WatcherConfig config,
    workloadapi_X509Callback
        x509callback /*, jwtBundleSetFunc_t* jwtBundleSetUpdateFunc*/,
    err_t *error)
{

    workloadapi_Watcher *newW
        = (workloadapi_Watcher *) calloc(1, sizeof *newW);

    // set by calloc:
    // newW->updated = false;
    // newW->closeError = NO_ERROR;
    // newW->update_error = NO_ERROR;
    // newW->threadError = thrd_success;

    newW->closed = true;

    if(config.client) {
        newW->client = config.client;
        newW->owns_client = false;
        if(config.client_options) {
            for(int i = 0; i < arrlen(config.client_options); i++) {
                workloadapi_Client_ApplyOption(config.client,
                                               config.client_options[i]);
            }
        }
    } else {
        newW->client = workloadapi_NewClient(error);
        if(*error != NO_ERROR) {
            free(newW);
            return NULL;
        }
        newW->owns_client = true;
        if(config.client_options) {
            for(int i = 0; i < arrlen(config.client_options); i++) {
                workloadapi_Client_ApplyOption(newW->client,
                                               config.client_options[i]);
            }
        }
    }

    /// TODO: check if callback is valid?
    newW->x509callback = x509callback;

    int thread_error = mtx_init(&(newW->closeMutex), mtx_plain);
    if(thread_error != thrd_success) {
        /// TODO: return thread error?
        *error = ERROR2;
        return NULL;
    }
    thread_error = mtx_init(&(newW->update_mutex), mtx_plain);
    if(thread_error != thrd_success) {
        /// TODO: return thread error?
        *error = ERROR2;
        return NULL;
    }
    thread_error = cnd_init(&(newW->update_cond));
    if(thread_error != thrd_success) {
        /// TODO: return thread error?
        *error = ERROR2;
        return NULL;
    }

    return newW;
}

// starts watcher and blocks waiting on an update.
err_t workloadapi_Watcher_Start(workloadapi_Watcher *watcher)
{
    err_t error = NO_ERROR;
    if(!watcher) {
        return ERROR1; /// NULL WATCHER;
    }
    error = workloadapi_Client_Connect(watcher->client);
    if(error != NO_ERROR) {
        return error;
    }
    /// spin watcher thread out.
    int thread_error
        = thrd_create(&(watcher->watcherThread),
                      workloadapi_Watcher_X509backgroundFunc, watcher);

    if(thread_error != thrd_success) {
        watcher->threadError = thread_error;
        return ERROR2; // THREAD ERROR, see watcher->threadERROR for error
    }
    /// wait for update and check for errors.
    error = workloadapi_Watcher_WaitUntilUpdated(watcher);
    if(error != NO_ERROR) {
        /// TODO: add error handling and destroy thread. error is already set
        /// so we just need to get our bearings and deallocate stuff;
        watcher->update_error = error;
        return ERROR3;
    }
    return error;
}

// drops connection to WorkloadAPI (if owns client)
err_t workloadapi_Watcher_Close(workloadapi_Watcher *watcher)
{
    mtx_lock(&(watcher->closeMutex));
    watcher->closed = true;
    err_t error = NO_ERROR;
    /// TODO: check and set watcher->closeError?
    if(watcher->owns_client) {

        error = workloadapi_Client_Close(watcher->client);
        if(error != NO_ERROR) {

            watcher->closeError = error;
            mtx_unlock(&(watcher->closeMutex));
            return error;
        }
        error = workloadapi_Client_Free(watcher->client);
        if(error != NO_ERROR) {
            // shouldn't reach here.
        }
    }
    mtx_unlock(&(watcher->closeMutex));
    int join_return;
    int thread_error = thrd_join(watcher->watcherThread, &join_return);
    if(thread_error == thrd_success) {
        return (err_t) join_return;
    }
    return ERROR2;
}

// drops connection to WorkloadAPI (if owns client) MUST ALREADY BE CLOSED.
err_t workloadapi_Watcher_Free(/*context,*/ workloadapi_Watcher *watcher)
{
    /// TODO: free watcher
    mtx_destroy(&(watcher->closeMutex));
    cnd_destroy(&(watcher->update_cond));
    mtx_destroy(&(watcher->update_mutex));
    if(watcher->owns_client) {
        /// TODO: call freeClient();
    }
    free(watcher);
    return NO_ERROR;
}

// Function called by Client when new x509 response arrives
void workloadapi_Watcher_OnX509ContextUpdate(workloadapi_Watcher *watcher,
                                             workloadapi_X509Context *context)
{
    void *args = watcher->x509callback.args;
    watcher->x509callback.func(context, args);
    workloadapi_Watcher_TriggerUpdated(watcher);
}

// Called by Client when an error occurs
void workloadapi_Watcher_OnX509ContextWatchError(workloadapi_Watcher *watcher,
                                                 err_t error)
{
    /// TODO: catch/recover/exit from watch error
    /// INFO: go-spiffe does nothing.
}

err_t workloadapi_Watcher_WaitUntilUpdated(workloadapi_Watcher *watcher)
{
    return workloadapi_Watcher_TimedWaitUntilUpdated(watcher, NULL);
}

err_t workloadapi_Watcher_TimedWaitUntilUpdated(workloadapi_Watcher *watcher,
                                                struct timespec *timer)
{
    mtx_lock(&watcher->update_mutex);
    if(watcher->updated) {
        mtx_unlock(&watcher->update_mutex);
        return NO_ERROR;
    } else {
        int thread_error = thrd_success;
        if(timer != NULL) {
            thread_error = cnd_timedwait(&(watcher->update_cond),
                                         &(watcher->update_mutex), timer);
            if(thread_error == thrd_timedout) {
                mtx_unlock(&(watcher->update_mutex));
                return ERROR1; // timed out
            }
        } else {
            thread_error
                = cnd_wait(&(watcher->update_cond), &(watcher->update_mutex));
        }
        mtx_unlock(&watcher->update_mutex);
        if(thread_error != thrd_success) {
            return ERROR2;
        } else {
            return NO_ERROR;
        }
    }
}

err_t workloadapi_Watcher_TriggerUpdated(workloadapi_Watcher *watcher)
{

    mtx_lock(&(watcher->update_mutex));

    watcher->updated = true;
    cnd_broadcast(&(watcher->update_cond));
    mtx_unlock(&(watcher->update_mutex));

    return NO_ERROR; /// TODO: error checking?
}
