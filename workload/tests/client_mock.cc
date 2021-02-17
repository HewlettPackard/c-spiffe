
#include "../../internal/x509util/src/util.h"

#include <grpc/grpc.h>
#include <grpcpp/grpcpp.h>
#include "workload.pb.h"
#include "workload.grpc.pb.h"
#include "../../svid/x509svid/src/svid.h"
#include "../../bundle/x509bundle/src/bundle.h"
#include "../../bundle/x509bundle/src/set.h"
#include "../src/client.h"

x509bundle_Bundle *workloadapi_parseX509Bundle(string_t id, const byte *bundle_bytes, const size_t len, err_t *err)
{
    *err = NO_ERROR;
    return NULL;
}

x509bundle_Set *workloadapi_parseX509Bundles(const X509SVIDResponse *rep, err_t *err)
{
    *err = NO_ERROR;
    return NULL;
}

x509svid_SVID** workloadapi_parseX509SVIDs(X509SVIDResponse *resp,
                                            bool firstOnly,
                                            err_t *err){
    *err = NO_ERROR;
    return NULL;
}

workloadapi_X509Context* workloadapi_parseX509Context(X509SVIDResponse *resp, err_t *err){
    
    *err = NO_ERROR;
    return NULL;
}


workloadapi_Client *workloadapi_NewClient(err_t *error)
{
    *error = NO_ERROR;
    return NULL;
}

err_t workloadapi_Client_Free(workloadapi_Client *client)
{
    return NO_ERROR;
}

err_t workloadapi_Client_Connect(workloadapi_Client *client)
{
    return NO_ERROR;
}

err_t workloadapi_Client_Close(workloadapi_Client *client)
{
    return NO_ERROR;
}

err_t workloadapi_Client_SetAddress(workloadapi_Client *client, const char *address)
{
    ///QUESTION: should we do anything else like printing stuff?
    return NO_ERROR;
}

err_t workloadapi_Client_AddHeader(workloadapi_Client *client, const char *key, const char *value)
{
    return NO_ERROR;
}

err_t workloadapi_Client_SetHeader(workloadapi_Client *client, const char *key, const char *value)
{
    return NO_ERROR;
}

err_t workloadapi_Client_ClearHeaders(workloadapi_Client *client)
{
    return NO_ERROR;
}

err_t workloadapi_Client_SetStub(workloadapi_Client* client, workloadapi_Stub stub){
    return NO_ERROR;
}

void workloadapi_Client_setDefaultAddressOption(workloadapi_Client *client, void *not_used)
{
}

void workloadapi_Client_setDefaultHeaderOption(workloadapi_Client *client, void *not_used)
{
}

void workloadapi_Client_ApplyOption(workloadapi_Client *client, workloadapi_ClientOption option)
{
    workloadapi_Client_ApplyOptionWithArg(client, option, NULL);
}

void workloadapi_Client_ApplyOptionWithArg(workloadapi_Client *client, workloadapi_ClientOption option, void *arg)
{
}

void workloadapi_Client_defaultOptions(workloadapi_Client *client, void *not_used)
{
}

err_t workloadapi_Client_WatchX509Context(workloadapi_Client* client, workloadapi_Watcher* watcher){
    return NO_ERROR;
}

err_t workloadapi_Client_watchX509Context(workloadapi_Client* client, workloadapi_Watcher* watcher, workloadapi_Backoff *backoff){
    return NO_ERROR;
}

err_t workloadapi_Client_HandleWatchError(workloadapi_Client* client, err_t error, workloadapi_Backoff *backoff){    
    return NO_ERROR;
}


workloadapi_X509Context* workloadapi_Client_FetchX509Context(workloadapi_Client* client, err_t* error){
    *error = NO_ERROR;
    return NULL;
}

x509bundle_Set* workloadapi_Client_FetchX509Bundles(workloadapi_Client* client, err_t *err)
{
    *error = NO_ERROR;
    return NULL; //no response -> no bundle
}

x509svid_SVID** workloadapi_Client_FetchX509SVIDs(workloadapi_Client* client, err_t *err)
{    
    *error = NO_ERROR;
    return NULL; //no response -> no bundle
}


x509svid_SVID* workloadapi_Client_FetchX509SVID(workloadapi_Client* client, err_t *err)
{    
    *error = NO_ERROR;
    return NULL;
}

