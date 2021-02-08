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
typedef void* stub_ptr;
typedef void* conn_ptr;

//a clientOption is a function that modifies a ClientConfig

typedef struct workloadapi_Client {
    stub_ptr stub;
    conn_ptr conn;
    
    char* address;
    ///TODO:logger
    ///TODO: dialOptions //do gRPC :(
} workloadapi_Client;

//ClientOptions are functions, that will modify the client, with an optional argument. 
typedef void (*ClientOption)(workloadapi_Client*,void*);



///TODO: IMPLEMENT on client.cc:

workloadapi_Client* workloadapi_NewClient(ClientOption option,err_t* error);
err_t workloadapi_newConn(workloadapi_Client *client);
err_t workloadapi_Close(workloadapi_Client *client);
err_t workloadapi_WatchX509Context(workloadapi_Client* client, workloadapi_Watcher* watcher); //public function
err_t workloadapi_watchX509Context(workloadapi_Client* client, workloadapi_Watcher* Watcher, Backoff *backoff); //used internally
workloadapi_X509Context FetchX509Context(workloadapi_Client* client, err_t* error);
err_t workloadapi_handleWatchError(workloadapi_Client* client, err_t error, Backoff *backoff);
x509svid_SVID* FetchX509SVID(workloadapi_Client* client, err_t* error);
x509svid_SVID* FetchX509SVIDs(workloadapi_Client* client, err_t* error);

 //default options for client. must set all 
void workloadapi_defaultClientOptions(workloadapi_Client* client);
err_t workloadapi_setAddress(workloadapi_Client *client, const char* address);

///DONE: implemented in client.cc, not part of public interface:
 
// x509bundle_Set* workloadapi_parseX509Bundles(const X509SVIDResponse *rep, 
//                                             err_t *err);
// x509bundle_Bundle* workloadapi_parseX509Bundle(string_t id,
//                                             const byte *bundle_bytes,
//                                             const size_t len,
//                                             err_t *err);

///TODO: define in client.cc:

// x509SVID_svid** parseX509SVIDs(X509SVIDResponse *resp,
                                            // bool firstOnly,
                                            // err_t *err)
// workloadapi_X509Context parseX509Context(X509SVIDResponse *resp, err_t err); //implemented on fetchX509Context

///TODO: migrate from Requestor??

// workloadapi_Client* workloadapi_ClientInit(const char* address);
// workloadapi_Client* workloadapi_ClientInitWithStub(const char* address,stub_ptr stub);
// void workloadapi_ClientFree(workloadapi_Client* client);
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

///DROPPED: (for now, check back later)
//withHeader(); //the header will be added at connection time.

#ifdef __cplusplus
}
#endif

#endif
