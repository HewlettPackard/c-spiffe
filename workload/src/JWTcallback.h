#ifndef INCLUDE_WORKLOAD_JWTCALLBACK_H
#define INCLUDE_WORKLOAD_JWTCALLBACK_H

#include "../../bundle/jwtbundle/src/set.h"
#include "../../svid/jwtsvid/src/svid.h"

#ifdef __cplusplus
extern "C"{
#endif

/** type for callback function. will be set by JWTSource. */
typedef void(*workloadapi_jwtBundleSetFunc_t)(jwtbundle_Set*);

typedef struct {
    void *args;
    workloadapi_jwtBundleSetFunc_t func;
} workloadapi_JWTCallback;

#ifdef __cplusplus
}
#endif

#endif // INCLUDE_WORKLOAD_JWTCALLBACK_H
