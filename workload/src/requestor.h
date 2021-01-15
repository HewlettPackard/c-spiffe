#ifndef _REQUESTOR_H_
#define _REQUESTOR_H_
  #ifdef __cplusplus
#define EXTERN_C extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C
#define EXTERN_C_END
#endif
#include "x509svid/src/svid.h"
#include <pthread.h>
EXTERN_C
typedef struct Requestor {
    //TODO: keep tabs on threads?
    //pthread_t** threads;

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
void RequestorFree(Requestor* requestor);

// StreamResponse RequestorRequestStream(Requestor* requestor, Request request, (void*)(*callback)(void*));
// Response RequestorRequest(Requestor* requestor,Request request);

//wrapper methods from gRPC service definition (see proto/workload.proto)
x509svid_SVID* FetchDefaultX509SVID(Requestor* requestor); //not in definition
int FetchAllX509SVID(Requestor* requestor, x509svid_SVID** svids); //not in definition
// x509svid_SVID_Source* FetchX509SVIDSource(Requestor* requestor);
EXTERN_C_END
#endif /* _REQUESTOR_H_ */
