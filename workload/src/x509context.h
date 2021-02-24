#ifndef INCLUDE_WORKLOAD_X509CONTEXT_H
#define INCLUDE_WORKLOAD_X509CONTEXT_H

#include "../../bundle/x509bundle/src/set.h"
#include "../../svid/x509svid/src/svid.h"

#ifdef __cplusplus
extern "C"{
#endif

typedef struct workloadapi_X509Context {
    x509svid_SVID **svids;
    x509bundle_Set *bundles;

} workloadapi_X509Context;

// type for callback function. will be set by X509Source.
typedef void (*workloadapi_x509ContextFunc_t)(workloadapi_X509Context *,
                                              void *);
// eg.:
// workloadapi_x509ContextFunc_t func; -> void
// (*func)(workloadapi_X509Context* updatedContext);

typedef struct X509Callback {
    void *args;
    workloadapi_x509ContextFunc_t func;
} workloadapi_X509Callback;

#ifdef __cplusplus
}
#endif

#endif // INCLUDE_WORKLOAD_X509CONTEXT_H
