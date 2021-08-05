#include "c-spiffe/bundle/jwtbundle.h"
#include "c-spiffe/workload/workload.h"
#include "threads.h"

void callback_X509Context(workloadapi_X509Context *ctx, void *unused)
{
    // dummy
}

void callback_JWTBundles(jwtbundle_Set *set, void *unused)
{
    // dummy
}

int watch_X509SVIDs(void *arg)
{
    workloadapi_Client *client = arg;
    /// TODO: configure watcher
    workloadapi_WatcherConfig config
        = { .client = client, .client_options = NULL };
    workloadapi_X509Callback cb
        = { .args = NULL, .func = callback_X509Context };
    err_t err;
    workloadapi_Watcher *watcher = workloadapi_newWatcher(config, cb, &err);
    if(!watcher || err) {
        printf("Failed creating X.509 watcher: %u\n", err);
        return -1;
    }

    err = workloadapi_Client_WatchX509Context(client, watcher);
    if(err) {
        printf("Failed watching X.509 context: %u\n", err);
    }

    err = workloadapi_Watcher_Close(watcher);
    if(err) {
        printf("Failed closing X.509 watcher: %u\n", err);
    }
    workloadapi_Watcher_Free(watcher);

    return 0;
}

int watch_JWTBundles(void *arg)
{
    workloadapi_Client *client = arg;
    /// TODO: configure watcher
    workloadapi_JWTWatcherConfig config
        = { .client = client, .client_options = NULL };
    workloadapi_JWTCallback cb = { .args = NULL, .func = callback_JWTBundles };
    err_t err;
    workloadapi_JWTWatcher *watcher
        = workloadapi_newJWTWatcher(config, cb, &err);
    if(!watcher || err) {
        printf("Failed creating JWT watcher: %u\n", err);
        return -1;
    }

    err = workloadapi_Client_WatchJWTBundles(client, watcher);
    if(err) {
        printf("Failed watching JWT bundles: %u\n", err);
    }

    err = workloadapi_JWTWatcher_Close(watcher);
    if(err) {
        printf("Failed closing JWT watcher: %u\n", err);
    }
    workloadapi_JWTWatcher_Free(watcher);

    return 0;
}

void startWatchers(void)
{
    thrd_t thrd_x509, thrd_jwt;
    err_t err;
    workloadapi_Client *client = workloadapi_NewClient(&err);
    if(!client || err) {
        printf("Failed creating client: %u\n", err);
        return;
    }

    workloadapi_Client_defaultOptions(client, NULL);
    err = workloadapi_Client_Connect(client);
    if(err) {
        printf("Failed connecting client: %u\n", err);
        return;
    }

    thrd_create(&thrd_x509, watch_X509SVIDs, client);
    thrd_create(&thrd_jwt, watch_JWTBundles, client);

    thrd_join(&thrd_x509, NULL);
    thrd_join(&thrd_jwt, NULL);

    err = workloadapi_Client_Close(client);
    if(err) {
        printf("Failed closing client: %u\n", err);
    }
    workloadapi_Client_Free(client);
}

int main(void)
{
    startWatchers();

    return 0;
}
