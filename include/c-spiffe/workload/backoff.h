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

#ifndef INCLUDE_WORKLOAD_BACKOFF_H
#define INCLUDE_WORKLOAD_BACKOFF_H

#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/** backoff defines an linear backoff policy.
 * */
typedef struct {
    /** initial wait time for backoff */
    struct timespec initial;

    /** maximum wait time */
    struct timespec max;

    int times;
} workloadapi_Backoff;

/** constructor with default settings */
workloadapi_Backoff workloadapi_NewDefaultBackoff();

/** constructor */
workloadapi_Backoff workloadapi_NewBackoff(struct timespec initial,
                                           struct timespec max);

/** returns a timestamp for use in cnd_timedwait() */
struct timespec workloadapi_Backoff_NextTime(workloadapi_Backoff *backoff);

/** resets backoff. */
void workloadapi_Backoff_Reset(workloadapi_Backoff *backoff);

#ifdef __cplusplus
}
#endif

#endif // INCLUDE_WORKLOAD_BACKOFF_H
