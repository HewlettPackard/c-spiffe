#ifndef BACKOFF_H
#define BACKOFF_H

#include <time.h>

const timespec SECOND = timespec{1,0};

typedef struct Backoff
{
    timespec initial; //initial wait time for backoff
    timespec max;
    int times;

} Backoff;

Backoff newDefaultBackoff(); // constructor with default settings
Backoff newBackoff(timespec initial, timespec max); //constructor
timespec nextTime(Backoff* backoff); // returns a timestamp
void resetBackoff(Backoff* backoff);

#endif //BACKOFF_H