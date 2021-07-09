#ifndef INCLUDE_WORKLOAD_CLIENT_H
#define INCLUDE_WORKLOAD_CLIENT_H

#include "c-spiffe/svid/jwtsvid/svid.h"
#include "c-spiffe/svid/x509svid/svid.h"
#include "c-spiffe/workload/backoff.h"
#include "c-spiffe/workload/jwtwatcher.h"
#include "c-spiffe/workload/watcher.h"
#include "c-spiffe/workload/x509context.h"

#ifdef __cplusplus
extern "C" {
#endif

/** pointer to gRPC construct, can't use those types in the header */
typedef void *workloadapi_Stub;    // api stub
typedef void *workloadapi_Context; // gRPC context with cancel utils

typedef struct workloadapi_Watcher workloadapi_Watcher;
typedef struct workloadapi_JWTWatcher workloadapi_JWTWatcher;

/** Client is a Workload API client.
 * */
typedef struct workloadapi_Client {
    workloadapi_Context *context_list;
    workloadapi_Stub stub;
    bool owns_stub;
    string_arr_t headers;
    string_t address;
    bool closed;
    mtx_t closed_mutex;
    cnd_t closed_cond;

} workloadapi_Client;

/** workloadapi_NewClient the Workload API and returns a client.
 * */
workloadapi_Client *workloadapi_NewClient(err_t *error);
err_t workloadapi_Client_Free(workloadapi_Client *client);
err_t workloadapi_Client_Connect(workloadapi_Client *client);

/** workloadapi_Client_Close closes the client. 
 * */
err_t workloadapi_Client_Close(workloadapi_Client *client);

/** ClientOptions are functions, that will modify the client, with an
 * optional argument. */
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

/** workloadapi_Client_WatchX509Context receives X509Context updates from the Workload API.
 * */
err_t workloadapi_Client_WatchX509Context(
    workloadapi_Client *client,
    workloadapi_Watcher *watcher); // public function

/** workloadapi_Client_watchX509Context watches for updates to the X.509 context. The watcher
 * receives the updated X.509 context
 */
err_t workloadapi_Client_watchX509Context(
    workloadapi_Client *client, workloadapi_Watcher *Watcher,
    workloadapi_Backoff *backoff); // used internally

err_t workloadapi_Client_HandleWatchError(workloadapi_Client *client,
                                          err_t error,
                                          workloadapi_Backoff *backoff);

/** workloadapi_Client_watchJWTBundles receives JWT bundle updates from the Workload API.
 * */
err_t workloadapi_Client_watchJWTBundles(workloadapi_Client *client,
                                         workloadapi_JWTWatcher *watcher,
                                         workloadapi_Backoff *backoff);

/** workloadapi_Client_WatchJWTBundles watches for changes to the JWT bundles. The watcher receives
 * the updated JWT bundles.
 */
err_t workloadapi_Client_WatchJWTBundles(workloadapi_Client *client,
                                         workloadapi_JWTWatcher *watcher);

/** workloadapi_Client_FetchX509Context fetches the X.509 context, which contains both X509-SVIDs
 * and X.509 bundles.
 */
workloadapi_X509Context *
workloadapi_Client_FetchX509Context(workloadapi_Client *client, err_t *error);
x509bundle_Set *workloadapi_Client_FetchX509Bundles(workloadapi_Client *client,
                                                    err_t *error);

/** workloadapi_Client_FetchX509SVID fetches the default X509-SVID, i.e. the first in the list
 * returned by the Workload API.
 * */
x509svid_SVID *workloadapi_Client_FetchX509SVID(workloadapi_Client *client,
                                                err_t *error);

/** workloadapi_Client_FetchX509SVIDs fetches all X509-SVIDs.
 * */
x509svid_SVID **workloadapi_Client_FetchX509SVIDs(workloadapi_Client *client,
                                                  err_t *error);

/** workloadapi_Client_FetchJWTSVID fetches a JWT-SVID.
 */
jwtsvid_SVID *workloadapi_Client_FetchJWTSVID(workloadapi_Client *client,
                                              jwtsvid_Params *params,
                                              err_t *err);

/** workloadapi_Client_FetchJWTBundles fetches the JWT bundles for JWT-SVID validation, keyed
 * by a SPIFFE ID of the trust domain to which they belong.
 * */
jwtbundle_Set *workloadapi_Client_FetchJWTBundles(workloadapi_Client *client,
                                                  err_t *err);
                                         
/** workloadapi_Client_ValidateJWTSVID validates the JWT-SVID token. The parsed and validated
 * JWT-SVID is returned.
 */
jwtsvid_SVID *workloadapi_Client_ValidateJWTSVID(workloadapi_Client *client,
                                                 char *token, char *audience,
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
