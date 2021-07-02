#ifndef INCLUDE_WORKLOAD_X509CONTEXT_H
#define INCLUDE_WORKLOAD_X509CONTEXT_H

#include "c-spiffe/bundle/x509bundle/set.h"
#include "c-spiffe/svid/x509svid/svid.h"

#ifdef __cplusplus
extern "C" {
#endif

/** workloadapi_X509Context conveys X.509 materials from the Workload API.
 * */
typedef struct {
    x509svid_SVID **svids;
    /* Bundles is a set of X.509 bundles. */
    x509bundle_Set *bundles;

} workloadapi_X509Context;

/** type for callback function. will be set by X509Source. */
typedef void (*workloadapi_x509ContextFunc_t)(workloadapi_X509Context *,
                                              void *);
// eg.:
// workloadapi_x509ContextFunc_t func; -> void
// (*func)(workloadapi_X509Context* updatedContext);

typedef struct {
    void *args;
    workloadapi_x509ContextFunc_t func;
} workloadapi_X509Callback;

#ifdef __cplusplus
}
#endif

#endif // INCLUDE_WORKLOAD_X509CONTEXT_H
