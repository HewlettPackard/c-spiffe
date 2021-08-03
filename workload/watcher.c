#include "c-spiffe/workload/watcher.h"
#include "c-spiffe/workload/client.h"
#include "c-spiffe/workload/x509context.h"
#include "c-spiffe/workload/x509source.h"

// Function that will run on thread spun for watcher
int workloadapi_Watcher_X509backgroundFunc(void *_watcher)
{
    workloadapi_Watcher *watcher = (workloadapi_Watcher *) _watcher;

    err_t error = NO_ERROR;
    do {
        error = workloadapi_Client_WatchX509Context(watcher->client, watcher);
    } while(error != ERR_INVALID_DATA && error != ERR_NULL
            && watcher->update_error == NO_ERROR);

    return (int) error;
}

// new watcher, creates client if not provided.
workloadapi_Watcher *
workloadapi_newWatcher(workloadapi_WatcherConfig config,
                       workloadapi_X509Callback x509callback, err_t *error)
{

    workloadapi_Watcher *newW
        = (workloadapi_Watcher *) calloc(1, sizeof *newW);

    // set by calloc:
    // newW->updated = false;
    // newW->close_error = NO_ERROR;
    // newW->update_error = NO_ERROR;
    // newW->thread_error = thrd_success;

    newW->closed = true;

    if(config.client) {
        newW->client = config.client;
        newW->owns_client = false;
        if(config.client_options) {
            for(size_t i = 0, size = arrlenu(config.client_options); i < size;
                ++i) {
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
            for(size_t i = 0, size = arrlenu(config.client_options); i < size;
                ++i) {
                workloadapi_Client_ApplyOption(newW->client,
                                               config.client_options[i]);
            }
        }
    }

    newW->x509callback = x509callback;

    int thread_error = mtx_init(&(newW->close_mutex), mtx_plain);
    if(thread_error != thrd_success) {
        *error = ERR_NULL;
        return NULL;
    }
    thread_error = mtx_init(&(newW->update_mutex), mtx_plain);
    if(thread_error != thrd_success) {
        *error = ERR_NULL;
        return NULL;
    }
    thread_error = cnd_init(&(newW->update_cond));
    if(thread_error != thrd_success) {
        *error = ERR_NULL;
        return NULL;
    }

    return newW;
}

// starts watcher and blocks waiting on an update.
err_t workloadapi_Watcher_Start(workloadapi_Watcher *watcher)
{
    err_t error = NO_ERROR;
    if(!watcher) {
        return ERR_NULL; /// NULL WATCHER;
    }
    error = workloadapi_Client_Connect(watcher->client);
    if(error != NO_ERROR) {
        return error;
    }
    /// spin watcher thread out.
    int thread_error
        = thrd_create(&(watcher->watcher_thread),
                      workloadapi_Watcher_X509backgroundFunc, watcher);

    if(thread_error != thrd_success) {
        watcher->thread_error = thread_error;
        return ERR_THREAD; // THREAD ERROR, see watcher->threadERROR for error
    }

    mtx_lock(&(watcher->close_mutex));
    watcher->closed = false;
    mtx_unlock(&(watcher->close_mutex));

    /// wait for update and check for errors.
    error = workloadapi_Watcher_WaitUntilUpdated(watcher);
    if(error != NO_ERROR) {
        mtx_lock(&(watcher->update_mutex));
        watcher->update_error = error;
        mtx_unlock(&(watcher->update_mutex));
        return ERR_WAITING;
    }

    return error;
}

// drops connection to WorkloadAPI (if owns client)
err_t workloadapi_Watcher_Close(workloadapi_Watcher *watcher)
{
    mtx_lock(&(watcher->close_mutex));
    watcher->closed = true;
    err_t error = NO_ERROR;
    if(watcher->owns_client) {

        error = workloadapi_Client_Close(watcher->client);
        if(error != NO_ERROR) {

            watcher->close_error = error;
            mtx_unlock(&(watcher->close_mutex));
            return error;
        }
    }
    mtx_unlock(&(watcher->close_mutex));
    int join_return;
    int thread_error = thrd_join(watcher->watcher_thread, &join_return);
    if(thread_error == thrd_success) {
        return (err_t) join_return;
    }
    return ERR_CLOSING;
}

// Free's Watcher (if owns client) MUST ALREADY BE CLOSED.
err_t workloadapi_Watcher_Free(/*context,*/ workloadapi_Watcher *watcher)
{
    mtx_destroy(&(watcher->close_mutex));
    cnd_destroy(&(watcher->update_cond));
    mtx_destroy(&(watcher->update_mutex));
    if(watcher->owns_client) {
        workloadapi_Client_Free(watcher->client);
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
    /// catch/recover/exit from watch error
    /// INFO: go-spiffe does nothing.
}

err_t workloadapi_Watcher_WaitUntilUpdated(workloadapi_Watcher *watcher)
{
    return workloadapi_Watcher_TimedWaitUntilUpdated(watcher, NULL);
}

err_t workloadapi_Watcher_TimedWaitUntilUpdated(workloadapi_Watcher *watcher,
                                                const struct timespec *timer)
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
                return ERR_TIMEOUT; // timed out
            }
        } else {
            thread_error
                = cnd_wait(&(watcher->update_cond), &(watcher->update_mutex));
        }
        mtx_unlock(&watcher->update_mutex);
        if(thread_error != thrd_success) {
            return ERR_WAITING;
        } else {
            return NO_ERROR;
        }
    }
}

err_t workloadapi_Watcher_TriggerUpdated(workloadapi_Watcher *watcher)
{
    err_t error = NO_ERROR;
    if(error = (err_t) mtx_lock(&(watcher->update_mutex))) {
        return error; // lock error
    }
    watcher->updated = true;
    if(error = (err_t) cnd_broadcast(&(watcher->update_cond))) {
        // save broadcast error, so if we also error on unlock
        // we have a way to check it
        watcher->thread_error = error;
    }
    if(error = (err_t) mtx_unlock(&(watcher->update_mutex))) {
        // if unlock
        return error;
    }
    if(!error) {
        return (err_t) watcher->thread_error;
    }
    return error;
}
