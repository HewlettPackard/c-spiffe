#ifndef __INCLUDE_WORKLOAD_CLIENT_H__
#define __INCLUDE_WORKLOAD_CLIENT_H__

#include "workload.pb.h"
#include "../../svid/x509svid/src/svid.h"
#include "../../bundle/x509bundle/src/set.h"
#include "../../utils/src/util.h"

#ifdef __cplusplus
extern "C" {
#endif

x509bundle_Set* workloadapi_parseX509Bundles(const X509SVIDResponse *rep, 
                                            err_t *err);
x509bundle_Bundle* workloadapi_parseX509Bundle(string_t id,
                                            const byte *bundle_bytes,
                                            const size_t len,
                                            err_t *err);

typedef void* stub_ptr;

typedef struct workloadapi_Client {
    //TODO: keep tabs on threads?
    //pthread_t** threads;
    stub_ptr stub;
    char* address;
} workloadapi_Client;

//constructor / destructor for workloadapi_Client
workloadapi_Client* workloadapi_ClientInit(const char* address);
workloadapi_Client* workloadapi_ClientInitWithStub(const char* address,stub_ptr stub);
void workloadapi_ClientFree(workloadapi_Client* client);

//wrapper methods from gRPC service definition (see proto/workload.proto)

// typedef struct clientConfig
// {
    
// } clientConfig;



///DONE: finished functions:
///func parseX509Bundles(resp *workload.X509SVIDResponse) (*x509bundle.Set, error) {
///func parseX509Bundle(spiffeID string, bundle []byte) (*x509bundle.Bundle, error) {

///TODO: IMPLEMENT on client.cc

// x509svid_SVID* workloadapi_FetchDefaultX509SVID(workloadapi_Client* client); //not in definition
// int workloadapi_FetchAllX509SVID(workloadapi_Client* client, x509svid_SVID*** svids); //not in definition
// x509bundle_Set* workloadapi_FetchX509Bundles(workloadapi_Client* client);

//workloadapi_Client* workloadapi_NewClient(ClientOption *options,err_t* error); 
err_t setAddress(workloadapi_Client *client);
err_t newConn(workloadapi_Client *client);
err_t Close(workloadapi_Client *client);

// clientConfig defaultClientConfig();

///TODO: ALL of those:

///func (c *Client) FetchX509SVID(ctx context.Context) (*x509svid.SVID, error) {
///func (c *Client) FetchX509SVIDs(ctx context.Context) ([]*x509svid.SVID, error) {
///func (c *Client) FetchX509Context(ctx context.Context) (*X509Context, error) {
///func (c *Client) WatchX509Context(ctx context.Context, watcher X509ContextWatcher) error {
///func (c *Client) handleWatchError(ctx context.Context, err error, backoff *backoff) error {
///func (c *Client) watchX509Context(ctx context.Context, watcher X509ContextWatcher, backoff *backoff) error {
///type X509ContextWatcher interface {
///func parseX509Context(resp *workload.X509SVIDResponse) (*X509Context, error) {
///func parseX509SVIDs(resp *workload.X509SVIDResponse, firstOnly bool) ([]*x509svid.SVID, error) {

///TODO: implement JWT later
///type JWTBundleWatcher interface {
///func parseJWTSVIDBundles(resp *workload.JWTBundlesResponse) (*jwtbundle.Set, error) {
///func (c *Client) FetchJWTSVID(ctx context.Context, params jwtsvid.Params) (*jwtsvid.SVID, error) {
///func (c *Client) FetchJWTBundles(ctx context.Context) (*jwtbundle.Set, error) {
///func (c *Client) WatchJWTBundles(ctx context.Context, watcher JWTBundleWatcher) error {
///func (c *Client) ValidateJWTSVID(ctx context.Context, token, audience string) (*jwtsvid.SVID, error) {
///func (c *Client) watchJWTBundles(ctx context.Context, watcher JWTBundleWatcher, backoff *backoff) error {

///DROPPED: (for now, check back later)
//withHeader(); //the header will be added at connection time.

#ifdef __cplusplus
}
#endif

#endif
