#ifndef INCLUDE_WORKLOAD_X509SOURCE_H
#define INCLUDE_WORKLOAD_X509SOURCE_H

#include "c-spiffe/bundle/x509bundle/set.h"
#include "c-spiffe/svid/x509svid/svid.h"
#include "c-spiffe/workload/watcher.h"
#include <threads.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    workloadapi_WatcherConfig watcher_config;
    x509svid_SVID *(*picker)(x509svid_SVID **);
} workloadapi_X509SourceConfig;

/** workloadapi_X509Source is a source of X509-SVIDs and X.509 bundles
 * maintained via the Workload API.
 * */
typedef struct {
    workloadapi_Watcher *watcher;
    workloadapi_X509SourceConfig *config;
    mtx_t mtx;
    mtx_t closed_mutex;
    bool closed;

    x509svid_SVID **svids;
    x509bundle_Set *bundles;
} workloadapi_X509Source;

/** workloadapi_NewX509Source creates a new X509Source. It blocks until the
 * initial update has been received from the Workload API.
 * */
workloadapi_X509Source *
workloadapi_NewX509Source(workloadapi_X509SourceConfig *config, err_t *err);
void workloadapi_X509Source_Free(workloadapi_X509Source *source);

err_t workloadapi_X509Source_Start(workloadapi_X509Source *source);

/** workloadapi_X509Source_Close closes the source, dropping the connection to
 * the Workload API. Other source methods will return an error after Close has
 * been called. The underlying Workload API client will also be closed if it is
 * owned by the X509Source (i.e. not provided via the WithClient option).
 * */
err_t workloadapi_X509Source_Close(workloadapi_X509Source *source);

err_t workloadapi_X509Source_checkClosed(workloadapi_X509Source *source);

/** workloadapi_X509Source_WaitUntilUpdated waits until the source is updated
 * or the context is done, in which case ctx.Err() is returned.
 * */
err_t workloadapi_X509Source_WaitUntilUpdated(workloadapi_X509Source *source);
void workloadapi_X509Source_applyX509Context(workloadapi_X509Source *source,
                                             workloadapi_X509Context *ctx);

/** workloadapi_X509Source_GetX509SVID returns an X509-SVID from the source. It
 * implements the x509svid.Source interface.
 * */
x509svid_SVID *
workloadapi_X509Source_GetX509SVID(workloadapi_X509Source *source, err_t *err);

/** workloadapi_X509Source_GetX509BundleForTrustDomain returns the X.509 bundle
 * for the given trust domain. It implements the x509bundle.Source interface.
 * */
x509bundle_Bundle *workloadapi_X509Source_GetX509BundleForTrustDomain(
    workloadapi_X509Source *source, const spiffeid_TrustDomain td, err_t *err);

#ifdef __cplusplus
}
#endif

#endif // INCLUDE_WORKLOAD_X509SOURCE_H
