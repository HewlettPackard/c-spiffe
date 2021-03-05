#ifndef INCLUDE_WORKLOAD_CLIENT_H
#define INCLUDE_WORKLOAD_CLIENT_H

#include "../../bundle/x509bundle/src/set.h"
#include "../../svid/jwtsvid/src/svid.h"
#include "../../svid/x509svid/src/svid.h"
#include "../../utils/src/util.h"
#include "backoff.h"
#include "watcher.h"
#include "jwt_watcher.h"
#include "x509context.h"

#ifdef __cplusplus
extern "C"
{
#endif

/** pointer to gRPC construct, can't use those types in the header */
typedef void *workloadapi_Stub; // api stub

typedef struct workloadapi_Watcher workloadapi_Watcher;
typedef struct workloadapi_JWTWatcher workloadapi_JWTWatcher;

typedef struct workloadapi_Client {
    workloadapi_Stub stub;
    bool owns_stub;
    string_arr_t headers;
    string_t address;
    bool closed;
    mtx_t closed_mutex;
    cnd_t closed_cond;

} workloadapi_Client;

workloadapi_Client *workloadapi_NewClient(err_t *error);
err_t workloadapi_Client_Free(workloadapi_Client *client);
err_t workloadapi_Client_Connect(workloadapi_Client *client);
err_t workloadapi_Client_Close(workloadapi_Client *client);

/** ClientOptions are functions, that will modify the client, with an optional argument. */
typedef void (*workloadapi_ClientOption)(workloadapi_Client *, void *);

err_t workloadapi_Client_SetAddress(workloadapi_Client *client,
                                    const char *address);
err_t workloadapi_Client_AddHeader(workloadapi_Client *client, const char *key,
                                   const char *value);
err_t workloadapi_Client_SetHeader(workloadapi_Client *client, const char *key,
                                   const char *value);
err_t workloadapi_Client_ClearHeaders(workloadapi_Client *client);
err_t workloadapi_Client_SetStub(workloadapi_Client *client,
                                 workloadapi_Stub stub);

void workloadapi_Client_ApplyOption(workloadapi_Client *client,
                                    workloadapi_ClientOption option);
void workloadapi_Client_ApplyOptionWithArg(workloadapi_Client *client,
                                           workloadapi_ClientOption option,
                                           void *arg);

void workloadapi_Client_setDefaultAddressOption(workloadapi_Client *client,
                                                void *not_used);
void workloadapi_Client_setDefaultHeaderOption(workloadapi_Client *client,
                                               void *not_used);

/** default options for client. must set all attributes */
void workloadapi_Client_defaultOptions(workloadapi_Client *client,
                                       void *not_used);

err_t workloadapi_Client_WatchX509Context(
    workloadapi_Client *client,
    workloadapi_Watcher *watcher); // public function

err_t workloadapi_Client_watchX509Context(
    workloadapi_Client *client, workloadapi_Watcher *Watcher,
    workloadapi_Backoff *backoff); // used internally

err_t workloadapi_Client_HandleWatchError(workloadapi_Client *client,
                                          err_t error,
                                          workloadapi_Backoff *backoff);

err_t workloadapi_Client_watchJWTBundles(workloadapi_Client *client,
                                         workloadapi_JWTWatcher *watcher,
                                         workloadapi_Backoff *backoff);

err_t workloadapi_Client_WatchJWTBundles(workloadapi_Client *client,
                                         workloadapi_JWTWatcher *watcher);

workloadapi_X509Context *
workloadapi_Client_FetchX509Context(workloadapi_Client *client, err_t *error);
x509bundle_Set *workloadapi_Client_FetchX509Bundles(workloadapi_Client *client,
                                                    err_t *error);
x509svid_SVID *workloadapi_Client_FetchX509SVID(workloadapi_Client *client,
                                                err_t *error);
x509svid_SVID **workloadapi_Client_FetchX509SVIDs(workloadapi_Client *client,
                                                  err_t *error);
jwtsvid_SVID *workloadapi_Client_FetchJWTSVID(workloadapi_Client *client,
                                              jwtsvid_Params *params,
                                              err_t *err);
/// Implemented in client.cc, not part of public API (Needs grpc Response
/// class, from C++)
// x509bundle_Set* workloadapi_parseX509Bundles(
//     const X509SVIDResponse *rep, err_t *err);
// x509bundle_Bundle* workloadapi_parseX509Bundle(string_t id,
//                                             const byte *bundle_bytes,
//                                             const size_t len,
//                                             err_t *err);
// jwtsvid_SVID* workloadapi_parseJWTSVID(
//     const JWTSVIDResponse *resp, jwtsvid_Params *params, err_t *err);
// jwtbundle_Set* workloadapi_parseJWTBundles(
//     const JWTBundlesResponse *resp, err_t *err);

#ifdef __cplusplus
}
#endif

#endif // INCLUDE_WORKLOAD_CLIENT_H
