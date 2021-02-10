#ifndef __INCLUDE_WORKLOAD_BACKOFF_H__
#define __INCLUDE_WORKLOAD_BACKOFF_H__

#include <time.h>

const struct timespec SECOND = {1,0};

typedef struct Backoff
{
    struct timespec initial; //initial wait time for backoff
    struct timespec max;
    int times;

} Backoff;

Backoff newDefaultBackoff(); // constructor with default settings
Backoff newBackoff(struct timespec initial, struct timespec max); //constructor
struct timespec nextTime(Backoff* backoff); // returns a timestamp
void resetBackoff(Backoff* backoff);

#endif //__INCLUDE_WORKLOAD_BACKOFF_H__