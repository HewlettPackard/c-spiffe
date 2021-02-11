#ifndef __INCLUDE_WORKLOAD_BACKOFF_H__
#define __INCLUDE_WORKLOAD_BACKOFF_H__

#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct workloadapi_Backoff
{
    struct timespec initial; //initial wait time for backoff
    struct timespec max;
    int times;

} workloadapi_Backoff;

workloadapi_Backoff workloadapi_NewDefaultBackoff(); // constructor with default settings
workloadapi_Backoff workloadapi_NewBackoff(struct timespec initial, struct timespec max); //constructor
struct timespec workloadapi_Backoff_NextTime(workloadapi_Backoff* backoff); // returns a timestamp
void workloadapi_Backoff_Reset(workloadapi_Backoff* backoff);

#endif //__INCLUDE_WORKLOAD_BACKOFF_H__
#ifdef __cplusplus

}

#endif