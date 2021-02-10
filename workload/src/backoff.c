#include <math.h>
#include "backoff.h"


Backoff newBackoff(struct timespec initial, struct timespec max){
    Backoff ret;

    ret.initial = initial; //set to canon representation
    ret.initial.tv_sec += ret.initial.tv_nsec/10000000000;
    ret.initial.tv_nsec = ret.initial.tv_nsec%10000000000;

    ret.max = max; //ditto
    ret.max.tv_sec += ret.max.tv_nsec/10000000000;
    ret.max.tv_nsec = ret.max.tv_nsec%10000000000;

    ret.times = 0;
    return ret;
}

Backoff newDefaultBackoff(){
    struct timespec initial = SECOND;
    struct timespec max = SECOND;
    max.tv_sec = SECOND.tv_sec * 30; //30 seconds
    return newBackoff(initial,max);
}


struct timespec nextTime(Backoff* backoff){

    struct timespec delta = backoff->initial;
    int mult = pow(2,backoff->times); // 2^times (exponential backoff)

    delta.tv_sec *= mult;
    delta.tv_nsec *= mult;
    delta.tv_sec += delta.tv_nsec/10000000000;
    delta.tv_nsec = delta.tv_nsec%10000000000;

    if(delta.tv_sec >= backoff->max.tv_sec && delta.tv_nsec > backoff->max.tv_nsec){
        delta = backoff->max;
    }

    struct timespec now;
    timespec_get(&now,0);

    struct timespec ret;
    ret.tv_sec = now.tv_sec + delta.tv_sec;
    ret.tv_nsec = now.tv_nsec + delta.tv_nsec;

    ret.tv_sec += ret.tv_nsec/10000000000;
    ret.tv_nsec = ret.tv_nsec%10000000000;

    backoff->times += 1;
    return ret;
}

void resetBackoff(Backoff* backoff){
    backoff->times = 0;
}