#ifndef INCLUDE_WORKLOAD_X509SOURCE_H
#define INCLUDE_WORKLOAD_X509SOURCE_H

#include "../../bundle/x509bundle/src/set.h"
#include "../../svid/x509svid/src/svid.h"
#include "watcher.h"
#include <threads.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct workloadapi_X509SourceConfig {
    workloadapi_WatcherConfig watcher_config;
    x509svid_SVID *(*picker)(x509svid_SVID **);
} workloadapi_X509SourceConfig;

typedef struct workloadapi_X509Source {
    workloadapi_Watcher *watcher;
    workloadapi_X509SourceConfig *config;
    mtx_t mtx;
    mtx_t closed_mutex;
    bool closed;

    x509svid_SVID **svids;
    x509bundle_Set *bundles;
} workloadapi_X509Source;

/// TODO: migrate to x509svid/
x509svid_SVID *x509svid_SVID_GetDefaultX509SVID(x509svid_SVID **svids);

workloadapi_X509Source *
workloadapi_NewX509Source(workloadapi_X509SourceConfig *config, err_t *err);
err_t workloadapi_X509Source_Close(workloadapi_X509Source *source);
x509svid_SVID *
workloadapi_X509Source_GetX509SVID(workloadapi_X509Source *source, err_t *err);
x509bundle_Bundle *workloadapi_X509Source_GetX509BundleForTrustDomain(
    workloadapi_X509Source *source, spiffeid_TrustDomain *td, err_t *err);
err_t workloadapi_X509Source_WaitUntilUpdated(workloadapi_X509Source *source);
// void workloadapi_X509Source_Updated();
void workloadapi_X509Source_applyX509Context(workloadapi_X509Source *source,
                                             workloadapi_X509Context *ctx);
err_t workloadapi_X509Source_checkClosed(workloadapi_X509Source *source);
void workloadapi_X509Source_Free(workloadapi_X509Source *source);

#ifdef __cplusplus
}
#endif

#endif // INCLUDE_WORKLOAD_X509SOURCE_H
