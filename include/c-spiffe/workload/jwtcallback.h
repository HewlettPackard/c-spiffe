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

#ifndef INCLUDE_WORKLOAD_JWTCALLBACK_H
#define INCLUDE_WORKLOAD_JWTCALLBACK_H

#include "c-spiffe/bundle/jwtbundle/set.h"

#ifdef __cplusplus
extern "C" {
#endif

/** type for callback function. will be set by JWTSource. */
typedef void (*workloadapi_jwtBundleSetFunc_t)(jwtbundle_Set *, void *);

typedef struct {
    void *args;
    workloadapi_jwtBundleSetFunc_t func;
} workloadapi_JWTCallback;

#ifdef __cplusplus
}
#endif

#endif // INCLUDE_WORKLOAD_JWTCALLBACK_H
