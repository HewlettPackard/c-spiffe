#ifndef __INCLUDE_WORKLOAD_X509CONTEXT_H__
#define __INCLUDE_WORKLOAD_X509CONTEXT_H__

#include "../../svid/x509svid/src/svid.h"
#include "../../bundle/x509bundle/src/set.h"


typedef struct workloadapi_X509Context
{
    x509svid_SVID** SVIDs;
    x509bundle_Set* Bundles;

} workloadapi_X509Context;

// type for callback function. will be set by X509Source.
typedef void (*workloadapi_x509ContextFunc_t)(workloadapi_X509Context*, void*); 
// eg.: 
// workloadapi_x509ContextFunc_t func; -> void (*func)(workloadapi_X509Context* updatedContext);

typedef struct X509Callback{
    void* args;
    workloadapi_x509ContextFunc_t func;
} workloadapi_X509Callback;


#endif //__INCLUDE_WORKLOAD_X509CONTEXT_H__