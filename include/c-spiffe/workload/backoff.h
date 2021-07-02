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
