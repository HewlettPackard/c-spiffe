#include "x509source.h"

typedef struct workloadapi_X509SourceConfig
{
    workloadapi_WatcherConfig watcher;
    x509svid_SVID* (*picker)(x509svid_SVID**);
} workloadapi_X509SourceConfig;

workloadapi_X509Source* workloadapi_NewX509Source(
    workloadapi_X509Context *ctx, err_t *err)
{
    workloadapi_X509SourceConfig *config = malloc(sizeof *config);
    memset(config, 0, sizeof *config);
    ///TODO: add X509SourceOption to set config

    workloadapi_X509Source *source = malloc(sizeof *source);
    source->picker = config->picker;

    ///TODO: initialize callback properly;
    workloadapi_X509Callback cb = {.args = NULL, .func = NULL};
    source->watcher = workloadapi_newWatcher(config->watcher, cb, err);

    if(!(*err))
    {
        return source;
    }

    workloadapi_X509Source_Free(source);
    return NULL;
}

err_t workloadapi_X509Source_Close(workloadapi_X509Source *source)
{
    mtx_lock(&(source->closedMtx));
    source->closed = true;
    mtx_unlock(&(source->closedMtx));

    return workloadapi_closeWatcher(source->watcher);
}

x509svid_SVID* workloadapi_X509Source_GetX509SVID(
    workloadapi_X509Source *source, x509svid_SVID *svid, err_t *err)
{
    *err = workloadapi_X509Source_checkClosed(source);
    if(!(*err))
    {
        mtx_lock(&(source->mtx));
        x509svid_SVID *svid = source->svid;
        mtx_unlock(&(source->mtx));

        if(svid)
        {
            return svid;
        }
        //missing SVID
        *err = ERROR1;
        return NULL;
    }

    return NULL;
}

x509bundle_Bundle* workloadapi_X509Source_GetX509BundleForTrustDomain(
    workloadapi_X509Source *source, spiffeid_TrustDomain td, err_t *err)
{
    *err = workloadapi_X509Source_checkClosed(source);
    if(!(*err))
    {
        return x509bundle_Set_GetX509BundleForTrustDomain(
                                    source->bundles, td, err);
    }

    return NULL;
}

err_t workloadapi_X509Source_WaitUntilUpdated(
    workloadapi_X509Source *source, workloadapi_X509Context *ctx)
{
    return workloadapi_Watcher_WaitUntilUpdated(source->watcher);
}

void workloadapi_X509Source_Updated()
{

}

void workloadapi_X509Source_setX509Context(
    workloadapi_X509Source *source, workloadapi_X509Context *ctx)
{
    x509svid_SVID *svid = source->picker? 
        source->picker(ctx->SVIDs) : ctx->SVIDs[0];

    mtx_lock(&(source->mtx));
    source->svid = svid;
    source->bundles = ctx->Bundles;
    mtx_unlock(&(source->mtx));
}

err_t workloadapi_X509Source_checkClosed(workloadapi_X509Source *source)
{
    err_t err = NO_ERROR;
    mtx_lock(&(source->closedMtx));
    if(source->closed)
    {
        //source is closed
        err = ERROR1;
    }
    mtx_unlock(&(source->closedMtx));
    return err;
}
