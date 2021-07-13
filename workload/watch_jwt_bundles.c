#include "c-spiffe/workload/jwtwatcher.h"

void print_function(jwtbundle_Set *set, void *not_used)
{
    jwtbundle_Set_Print(set);

}

int main(int argc, char const *argv[])
{
    workloadapi_JWTWatcherConfig config;
    config.client = NULL;
    config.client_options = NULL;
    arrpush(config.client_options, workloadapi_Client_defaultOptions);

    workloadapi_JWTCallback cb;
    cb.args = NULL;
    cb.func = print_function;

    err_t error = NO_ERROR;

    workloadapi_JWTWatcher *watcher
        = workloadapi_newJWTWatcher(config, cb, &error);

    if(error) {
        printf("error %d on newJWTWatcher()\n", error);
    }
    printf("press Enter to stop.\n");
    error = workloadapi_JWTWatcher_Start(watcher);

    if(error) {
        printf("error %d on JWTWatcher_Start()\n", error);
    }
    char ch;
    scanf("%c", &ch);

    printf("Stopping.\n");

    error = workloadapi_JWTWatcher_Close(watcher);
    if(error != ERR_CLOSING) {
        printf("error %d on JWTWatcher_Close()\n", error);
    }
    error = workloadapi_JWTWatcher_Free(watcher);
    if(error) {
        printf("error %d on JWTWatcher_Free()\n", error);
    }

    arrfree(config.client_options);

    return 0;
}
