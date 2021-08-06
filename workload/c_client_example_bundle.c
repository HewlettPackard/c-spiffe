/**
 *
 * (C) Copyright 2020-2021 Hewlett Packard Enterprise Development LP
 *
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 */

#include "c-spiffe/workload/client.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    if(argc < 2) {
        printf("Too few arguments!\nUsage:\n\t./c_client_bundle "
               "bundle_type=jwt\n\t./c_client_bundle bundle_type=x509\n");
        exit(-1);
    }

    err_t error = NO_ERROR;
    workloadapi_Client *client = workloadapi_NewClient(&error);
    if(error != NO_ERROR) {
        printf("client error! %d\n", (int) error);
    }
    workloadapi_Client_defaultOptions(client, NULL);
    error = workloadapi_Client_Connect(client);
    if(error != NO_ERROR) {
        printf("conn error! %d\n", (int) error);
    }

    if(strcmp(argv[1], "bundle_type=x509") == 0) {
        x509bundle_Set *set
            = workloadapi_Client_FetchX509Bundles(client, &error);
        if(error != NO_ERROR) {
            printf("fetch error! %d\n", (int) error);
        }
        printf("Address: %p\n", set);

        if(set) {
            printf("Bundles map Address: %p\n", set->bundles);
            printf("Number of Bundles: %lu\n", shlenu(set->bundles));
            if(shlenu(set->bundles)) {
                printf("1st Trust Domain: %s\n",
                       set->bundles[0].value->td.name);
            }
            x509bundle_Set_Free(set);
        }
    } else if(strcmp(argv[1], "bundle_type=jwt") == 0) {
        jwtbundle_Set *set
            = workloadapi_Client_FetchJWTBundles(client, &error);
        if(error != NO_ERROR) {
            printf("fetch error! %d\n", (int) error);
        }
        printf("Address: %p\n", set);

        if(set) {
            printf("Bundles map Address: %p\n", set->bundles);
            printf("Number of Bundles: %lu\n", shlenu(set->bundles));
            if(shlenu(set->bundles)) {
                printf("1st Trust Domain: %s\n",
                       set->bundles[0].value->td.name);
            }
            jwtbundle_Set_Free(set);
        }
    } else {
        printf("Invalid argument!\n");

        printf("Usage:\n\t./c_client_bundle "
               "bundle_type=jwt\n\t./c_client_bundle bundle_type=x509\n");
        exit(-1);
    }

    error = workloadapi_Client_Close(client);
    if(error != NO_ERROR) {
        printf("close error! %d\n", (int) error);
    }
    workloadapi_Client_Free(client);
    if(error != NO_ERROR) {
        printf("client free error! %d\n", (int) error);
    }

    return 0;
}
