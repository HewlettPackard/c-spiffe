#ifndef __INCLUDE_WORKLOAD_X509SOURCE_H__
#define __INCLUDE_WORKLOAD_X509SOURCE_H__

#include <threads.h>
#include "watcher.h"
#include "../../bundle/x509bundle/src/set.h"
#include "../../svid/x509svid/src/svid.h"

typedef struct workloadapi_X509Source
{
    workloadapi_Watcher *watcher;
    x509svid_SVID* (*picker)(x509svid_SVID**);

    mtx_t mtx;
    mtx_t closedMtx;
    bool closed;

    x509svid_SVID *svid;
    x509bundle_Set *bundles;
} workloadapi_X509Source;

workloadapi_X509Source* workloadapi_NewX509Source();
err_t workloadapi_X509Source_Close();
x509svid_SVID* workloadapi_X509Source_GetX509SVID();
x509bundle_Bundle* workloadapi_X509Source_GetX509BundleForTrustDomain();
err_t workloadapi_X509Source_WaitUntilUpdated();
void workloadapi_X509Source_Updated();
void workloadapi_X509Source_setX509Context();
err_t workloadapi_X509Source_checkClosed(workloadapi_X509Source *source);
void workloadapi_X509Source_Free(workloadapi_X509Source *source);

#endif
