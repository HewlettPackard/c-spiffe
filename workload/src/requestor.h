#ifndef _REQUESTOR_H_
#define _REQUESTOR_H_


#include "../../svid/x509svid/src/svid.h"
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef void* stub_ptr;

typedef struct Requestor {
    //TODO: keep tabs on threads?
    //pthread_t** threads;
    stub_ptr stub;
    char* address;
} Requestor;

typedef struct Request{
  int num_args;
  void** args;
} Request;

typedef struct Response{
  void* response;
  err_t error;
} Response;
typedef struct StreamResponse
{
  void* response;
  pthread_t *thread;
  err_t error;
} StreamResponse;

//constructor / destructor for Requestor
Requestor* RequestorInit(char* address);
Requestor* RequestorInitWithStub(char* address,stub_ptr stub);
void RequestorFree(Requestor* requestor);

// StreamResponse RequestorRequestStream(Requestor* requestor, Request request, (void*)(*callback)(void*));
// Response RequestorRequest(Requestor* requestor,Request request);

//wrapper methods from gRPC service definition (see proto/workload.proto)
x509svid_SVID* FetchDefaultX509SVID(Requestor* requestor); //not in definition
int FetchAllX509SVID(Requestor* requestor, x509svid_SVID*** svids); //not in definition
// x509svid_SVID_Source* FetchX509SVIDSource(Requestor* requestor);

#ifdef __cplusplus
}
#endif

#endif /* _REQUESTOR_H_ */
