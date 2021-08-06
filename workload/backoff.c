#include "c-spiffe/workload/backoff.h"
#include <math.h>

workloadapi_Backoff workloadapi_NewBackoff(struct timespec initial,
                                           struct timespec max)
{
    workloadapi_Backoff ret;

    ret.initial = initial; // set to canon representation
    ret.initial.tv_sec += ret.initial.tv_nsec / 10000000000;
    ret.initial.tv_nsec = ret.initial.tv_nsec % 10000000000;

    ret.max = max; // ditto
    ret.max.tv_sec += ret.max.tv_nsec / 10000000000;
    ret.max.tv_nsec = ret.max.tv_nsec % 10000000000;

    ret.times = 0;
    return ret;
}

workloadapi_Backoff workloadapi_NewDefaultBackoff()
{
    struct timespec initial = { 1, 0 };
    struct timespec max = { 30, 0 }; // 30 seconds
    return workloadapi_NewBackoff(initial, max);
}

struct timespec workloadapi_Backoff_NextTime(workloadapi_Backoff *backoff)
{

    struct timespec delta = backoff->initial;
    int mult = pow(2, backoff->times); // 2^times (exponential backoff)

    delta.tv_sec *= mult;
    delta.tv_nsec *= mult;
    delta.tv_sec += delta.tv_nsec / 10000000000;
    delta.tv_nsec = delta.tv_nsec % 10000000000;

    if(delta.tv_sec >= backoff->max.tv_sec
       && delta.tv_nsec > backoff->max.tv_nsec) {
        delta = backoff->max;
    }

    struct timespec now;
    timespec_get(&now, TIME_UTC);

    struct timespec ret;
    ret.tv_sec = now.tv_sec + delta.tv_sec;
    ret.tv_nsec = now.tv_nsec + delta.tv_nsec;

    ret.tv_sec += ret.tv_nsec / 10000000000;
    ret.tv_nsec = ret.tv_nsec % 10000000000;

    backoff->times += 1;
    return ret;
}

void workloadapi_Backoff_Reset(workloadapi_Backoff *backoff)
{
    backoff->times = 0;
}
