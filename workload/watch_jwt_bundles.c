
/**

(C) Copyright 2020-2021 Hewlett Packard Enterprise Development LP

 

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

 

    http://www.apache.org/licenses/LICENSE-2.0

 

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.

**/

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
