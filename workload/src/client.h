#ifndef __INCLUDE_WORKLOAD_CLIENT_H__
#define __INCLUDE_WORKLOAD_CLIENT_H__

#include "workload.pb.h"
#include "../../svid/x509svid/src/svid.h"
#include "../../bundle/x509bundle/src/set.h"
#include "../../utils/src/util.h"
#include "watcher.h"
#include "backoff.h"

#ifdef __cplusplus
extern "C" {
#endif

///pointer to gRPC constructs, can't use those types in the header
typedef void* stub_ptr; //api stub

typedef struct workloadapi_Client {
    stub_ptr stub;
    string_arr_t headers;
    string_t address;
    ///TODO:logger
    ///TODO: dialOptions //from gRPC :(

    bool closed;
} workloadapi_Client;

//ClientOptions are functions, that will modify the client, with an optional argument. 
typedef void (*workloadapi_ClientOption)(workloadapi_Client*,void*);

workloadapi_Client* workloadapi_NewClient(err_t* error);
err_t workloadapi_FreeClient(workloadapi_Client* client);
err_t workloadapi_ConnectClient(workloadapi_Client *client);
err_t workloadapi_CloseClient(workloadapi_Client *client);

err_t workloadapi_setClientAddress(workloadapi_Client *client, const char* address);
err_t workloadapi_addClientHeader(workloadapi_Client *client, const char* key, const char* value);
err_t workloadapi_clearClientHeaders(workloadapi_Client *client);
err_t workloadapi_setClientHeader(workloadapi_Client *client, const char* key, const char* value);

void workloadapi_applyClientOption(workloadapi_Client* client, workloadapi_ClientOption option);
void workloadapi_applyClientOptionWithArg(workloadapi_Client* client, workloadapi_ClientOption option, void* arg);

//default options for client. must set all attributes 
void workloadapi_defaultClientOptions(workloadapi_Client* client,void* not_used);

///TODO: IMPLEMENT on client.cc:

err_t workloadapi_setClientStub(workloadapi_Client* client, stub_ptr stub);

err_t workloadapi_WatchX509Context(workloadapi_Client* client, workloadapi_Watcher* watcher); //public function
err_t workloadapi_watchX509Context(workloadapi_Client* client, workloadapi_Watcher* Watcher, Backoff *backoff); //used internally
err_t workloadapi_handleWatchError(workloadapi_Client* client, err_t error, Backoff *backoff);

workloadapi_X509Context workloadapi_FetchX509Context(workloadapi_Client* client, err_t* error);
x509svid_SVID* workloadapi_FetchX509SVID(workloadapi_Client* client, err_t* error);
x509svid_SVID* workloadapi_FetchX509SVIDs(workloadapi_Client* client, err_t* error);


//setters for client, to be used inside ClientOption's
// err_t workloadapi_setClientConn(workloadapi_Client* client, conn_ptr conn);
///TODO: logger and dialOptions setters.
// err_t workloadapi_setLogger(workloadapi_Client* client, Logger* logger);
// err_t workloadapi_setDialOptions(workloadapi_Client* client, void* dialoption); //?????

///DONE: implemented in client.cc, not part of public interface:
 
x509bundle_Set* workloadapi_parseX509Bundles(const X509SVIDResponse *rep, 
                                            err_t *err);
x509bundle_Bundle* workloadapi_parseX509Bundle(string_t id,
                                            const byte *bundle_bytes,
                                            const size_t len,
                                            err_t *err);

///TODO: define in client.cc:

// x509SVID_svid** parseX509SVIDs(X509SVIDResponse *resp,
                                            // bool firstOnly,
                                            // err_t *err)
// workloadapi_X509Context parseX509Context(X509SVIDResponse *resp, err_t err); //implemented on fetchX509Context

///TODO: migrate from Requestor??

// workloadapi_Client* workloadapi_ClientInit(const char* address);
// workloadapi_Client* workloadapi_ClientInitWithStub(const char* address,stub_ptr stub);
// x509svid_SVID* workloadapi_FetchDefaultX509SVID(workloadapi_Client* client); //not in definition
// int workloadapi_FetchAllX509SVID(workloadapi_Client* client, x509svid_SVID*** svids); //not in definition
// x509bundle_Set* workloadapi_FetchX509Bundles(workloadapi_Client* client);

///TODO: implement JWT later
///type JWTBundleWatcher interface
///func parseJWTSVIDBundles(resp *workload.JWTBundlesResponse) (*jwtbundle.Set, error)
///func (c *Client) FetchJWTSVID(ctx context.Context, params jwtsvid.Params) (*jwtsvid.SVID, error)
///func (c *Client) FetchJWTBundles(ctx context.Context) (*jwtbundle.Set, error)
///func (c *Client) WatchJWTBundles(ctx context.Context, watcher JWTBundleWatcher) error
///func (c *Client) ValidateJWTSVID(ctx context.Context, token, audience string) (*jwtsvid.SVID, error)
///func (c *Client) watchJWTBundles(ctx context.Context, watcher JWTBundleWatcher, backoff *backoff) error

#ifdef __cplusplus
}
#endif

#endif
