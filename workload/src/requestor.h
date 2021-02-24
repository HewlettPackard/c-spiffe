#ifndef INCLUDE_WORKLOAD_REQUESTOR_H
#define INCLUDE_WORKLOAD_REQUESTOR_H

#include "../../bundle/x509bundle/src/set.h"
#include "../../svid/x509svid/src/svid.h"

#include <pthread.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef void *stub_ptr;

typedef struct workloadapi_Requestor {
    // TODO: keep tabs on threads?
    // pthread_t** threads;
    stub_ptr stub;
    char *address;
} workloadapi_Requestor;

typedef struct Request {
    int num_args;
    void **args;
} Request;

typedef struct Response {
    void *response;
    err_t error;
} Response;
typedef struct StreamResponse {
    void *response;
    pthread_t *thread;
    err_t error;
} StreamResponse;

// constructor / destructor for workloadapi_Requestor
workloadapi_Requestor *workloadapi_RequestorInit(const char *address);
workloadapi_Requestor *
workloadapi_RequestorInitWithStub(const char *address, stub_ptr stub);
void workloadapi_RequestorFree(workloadapi_Requestor *requestor);

// StreamResponse RequestorRequestStream(workloadapi_Requestor* requestor,
// Request request, (void*)(*callback)(void*)); Response
// RequestorRequest(workloadapi_Requestor* requestor,Request request);

// wrapper methods from gRPC service definition (see proto/workload.proto)
x509svid_SVID *workloadapi_FetchDefaultX509SVID(
    workloadapi_Requestor *requestor); // not in definition
int
workloadapi_FetchAllX509SVID(workloadapi_Requestor *requestor,
                                x509svid_SVID ***svids); // not in definition
// x509svid_SVID_Source* FetchX509SVIDSource(workloadapi_Requestor*
// requestor);

x509bundle_Set *
workloadapi_FetchX509Bundles(workloadapi_Requestor *requestor);

#ifdef __cplusplus
}
#endif

#endif /* _REQUESTOR_H_ */
