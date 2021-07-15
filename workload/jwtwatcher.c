#include "c-spiffe/workload/jwtwatcher.h"
#include "c-spiffe/workload/client.h"

// Function that will run on thread spun for watcher
int workloadapi_JWTWatcher_JWTbackgroundFunc(void *_watcher)
{
    workloadapi_JWTWatcher *watcher = (workloadapi_JWTWatcher *) _watcher;

    err_t error = NO_ERROR;
    do {
        error = workloadapi_Client_WatchJWTBundles(watcher->client, watcher);
    } while(error != ERR_INVALID_DATA && error != ERR_CLOSED
            && watcher->update_error == NO_ERROR);

    return (int) error;
}

// new watcher, creates client if not provided.
workloadapi_JWTWatcher *
workloadapi_newJWTWatcher(workloadapi_JWTWatcherConfig config,
                          workloadapi_JWTCallback jwt_callback, err_t *error)
{

    workloadapi_JWTWatcher *newW
        = (workloadapi_JWTWatcher *) calloc(1, sizeof *newW);

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
    newW->jwt_callback = jwt_callback;

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
err_t workloadapi_JWTWatcher_Start(workloadapi_JWTWatcher *watcher)
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
                      workloadapi_JWTWatcher_JWTbackgroundFunc, watcher);

    if(thread_error != thrd_success) {
        watcher->thread_error = thread_error;
        return ERR_THREAD; // THREAD ERROR, see watcher->threadERROR for error
    }

    mtx_lock(&(watcher->close_mutex));
    watcher->closed = false;
    mtx_unlock(&(watcher->close_mutex));

    error = workloadapi_JWTWatcher_WaitUntilUpdated(watcher);
    if(error != NO_ERROR) {
        mtx_lock(&(watcher->update_mutex));
        watcher->update_error = error;
        mtx_lock(&(watcher->update_mutex));
        return ERR_WAITING;
    }

    return error;
}

// drops connection to WorkloadAPI (if owns client)
err_t workloadapi_JWTWatcher_Close(workloadapi_JWTWatcher *watcher)
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

// Free's JWTWatcher (MUST ALREADY BE CLOSED)
err_t workloadapi_JWTWatcher_Free(/*context,*/ workloadapi_JWTWatcher *watcher)
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

// Function called by Client when new JWT response arrives
void workloadapi_JWTWatcher_OnJWTBundlesUpdate(workloadapi_JWTWatcher *watcher,
                                               jwtbundle_Set *set)
{
    void *args = watcher->jwt_callback.args;
    watcher->jwt_callback.func(set, args);
    workloadapi_JWTWatcher_TriggerUpdated(watcher);
}

// Called by Client when an error occurs
void workloadapi_JWTWatcher_OnJWTBundlesWatchError(
    workloadapi_JWTWatcher *watcher, err_t error)
{
    /// catch/recover/exit from watch error
    /// INFO: go-spiffe does nothing.
}

err_t workloadapi_JWTWatcher_WaitUntilUpdated(workloadapi_JWTWatcher *watcher)
{
    return workloadapi_JWTWatcher_TimedWaitUntilUpdated(watcher, NULL);
}

err_t workloadapi_JWTWatcher_TimedWaitUntilUpdated(
    workloadapi_JWTWatcher *watcher, const struct timespec *timer)
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

err_t workloadapi_JWTWatcher_TriggerUpdated(workloadapi_JWTWatcher *watcher)
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
