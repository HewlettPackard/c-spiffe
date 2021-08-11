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

#include "c-spiffe/bundle/jwtbundle.h"
#include "c-spiffe/internal/jwtutil.h"
#include "c-spiffe/workload/workload.h"
#include "threads.h"

#include <openssl/pem.h>

void callback_X509Context(workloadapi_X509Context *ctx, void *unused)
{
    if(ctx) {
        x509svid_SVID **svids = ctx->svids;

        for(size_t i = 0, size = arrlenu(svids); i < size; ++i) {
            string_t str_name = spiffeid_ID_String(svids[i]->id);
            printf("SVID updated for %s:\n", str_name);
            arrfree(str_name);

            X509 **certs = svids[i]->certs;
            for(size_t j = 0, size = arrlenu(certs); j < size; ++j) {
                PEM_write_X509(stdout, certs[j]);
            }
            putchar('\n');
        }
    }
}

void callback_JWTBundles(jwtbundle_Set *set, void *unused)
{
    if(set) {
        jwtbundle_Bundle **bundles = jwtbundle_Set_Bundles(set);

        for(size_t i = 0, size = arrlenu(bundles); i < size; ++i) {
            printf("jwt bundle updated %s:\n", bundles[i]->td.name);

            jwtutil_JWKS jwks
                = { .root = NULL,
                    .jwt_auths = jwtutil_CopyJWTAuthorities(bundles[i]->auths),
                    .x509_auths = NULL };
            err_t err = NO_ERROR;
            string_t str = jwtutil_JWKS_Marshal(&jwks, &err);

            if(str && err == NO_ERROR) {
                printf("%s\n", str);
            }

            arrfree(str);
            jwtutil_JWKS_Free(&jwks);
        }

        for(size_t i = 0, size = arrlenu(bundles); i < size; ++i) {
            jwtbundle_Bundle_Free(bundles[i]);
        }
    }
}

int watch_X509SVIDs(void *arg)
{
    workloadapi_Client *client = arg;
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
    workloadapi_JWTWatcherConfig config
        = { .client = client, .client_options = NULL };
    workloadapi_JWTCallback cb = { .args = NULL, .func = callback_JWTBundles };
    err_t err = NO_ERROR;
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

    thrd_join(thrd_x509, NULL);
    thrd_join(thrd_jwt, NULL);

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
