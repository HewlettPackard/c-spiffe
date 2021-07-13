#include "c-spiffe/workload/client.h"
#include "c-spiffe/bundle/x509bundle/bundle.h"
#include "c-spiffe/bundle/x509bundle/set.h"
#include "c-spiffe/internal/x509util/util.h"
#include "c-spiffe/svid/jwtsvid/parse.h"
#include "c-spiffe/svid/x509svid/svid.h"
#include "workload.grpc.pb.h"
#include "workload.pb.h"
#include <grpc/grpc.h>
#include <grpcpp/grpcpp.h>

x509bundle_Bundle *workloadapi_parseX509Bundle(const char *id,
                                               const byte *bundle_bytes,
                                               const size_t len, err_t *err)
{
    x509bundle_Bundle *bundle = NULL;

    if(id && bundle_bytes) {
        spiffeid_TrustDomain td = spiffeid_TrustDomainFromString(id, err);

        if(!(*err)) {
            X509 **certs = x509util_ParseCertificates(bundle_bytes, len, err);

            if(!(*err) && arrlenu(certs) > 0) {
                bundle = x509bundle_FromX509Authorities(td, certs);
            }
        }

        spiffeid_TrustDomain_Free(&td);
    }

    return bundle;
}

x509bundle_Set *workloadapi_parseX509Bundles(const X509SVIDResponse *rep,
                                             err_t *err)
{
    if(rep) {
        x509bundle_Set *set = x509bundle_NewSet(0);

        auto ids = rep->svids();
        for(auto &&id : ids) {
            err_t err;
            x509bundle_Bundle *b = workloadapi_parseX509Bundle(
                id.spiffe_id().c_str(),
                reinterpret_cast<const byte *>(id.bundle().data()),
                id.bundle().length(), &err);
            x509bundle_Set_Add(set, b);
        }

        auto map_td_bytes = rep->federated_bundles();
        for(auto const &td_byte : map_td_bytes) {
            err_t err;
            x509bundle_Bundle *b = workloadapi_parseX509Bundle(
                td_byte.first.c_str(),
                reinterpret_cast<const byte *>(td_byte.second.data()),
                td_byte.second.length(), &err);
            x509bundle_Set_Add(set, b);
        }

        return set;
    }
    // null pointer error
    *err = ERR_NULL;
    return NULL;
}

x509svid_SVID **workloadapi_parseX509SVIDs(X509SVIDResponse *resp,
                                           bool firstOnly, err_t *err)
{
    if(!resp) {
        *err = ERR_PARSING;
        return NULL;
    }
    x509svid_SVID **x509svids = NULL;
    *err = NO_ERROR;
    for(auto &&id : resp->svids()) {
        // assemble SVID from response.
        auto x509svid = x509svid_ParseRaw((byte *) id.x509_svid().data(),
                                          id.x509_svid().length(),
                                          (byte *) id.x509_svid_key().data(),
                                          id.x509_svid_key().length(), err);
        if(*err != NO_ERROR)
            return NULL;
        else
            arrpush(x509svids, x509svid);
        if(firstOnly)
            break; // first SVID done.
    }
    return x509svids;
}

workloadapi_X509Context *workloadapi_parseX509Context(X509SVIDResponse *resp,
                                                      err_t *err)
{
    auto svids = workloadapi_parseX509SVIDs(resp, false, err);
    if(*err != NO_ERROR) {
        return NULL;
    }
    auto bundles = workloadapi_parseX509Bundles(resp, err);
    if(*err != NO_ERROR) {
        for(int i = 0; i < arrlen(svids); i++) {
            x509svid_SVID_Free(svids[i]);
        }
        arrfree(svids);
        return NULL;
    }
    *err = NO_ERROR;
    workloadapi_X509Context *cntx
        = (workloadapi_X509Context *) calloc(1, sizeof *cntx);
    if(!cntx) {
        for(int i = 0; i < arrlen(svids); i++) {
            x509svid_SVID_Free(svids[i]);
        }
        arrfree(svids);
        x509bundle_Set_Free(bundles);
        *err = ERR_PARSING;
        return NULL;
    }
    cntx->bundles = bundles;
    cntx->svids = svids;

    return cntx;
}

jwtsvid_SVID *workloadapi_parseJWTSVID(const JWTSVIDResponse *resp,
                                       jwtsvid_Params *params, err_t *err)
{
    if(resp) {
        // insert audience at the beginning of the array
        if(params->audience) {
            arrins(params->extra_audiences, 0, params->audience);
            // for memory safety
            params->audience = NULL;
        }

        if(resp->svids_size() > 0) {
            auto id = resp->svids(0);
            string_t token = string_new(id.svid().c_str());
            jwtsvid_SVID *svid
                = jwtsvid_ParseInsecure(token, params->extra_audiences, err);
            arrfree(token);

            return svid;
        } else {
            // no SVID returned
            *err = ERR_NULL_SVID;
            return NULL;
        }
    }
    // null pointer error
    *err = ERR_NULL;
    return NULL;
}

jwtbundle_Set *workloadapi_parseJWTBundles(const JWTBundlesResponse *resp,
                                           err_t *err)
{
    if(resp) {
        jwtbundle_Set *set = jwtbundle_NewSet(0);

        auto map_td_bytes = resp->bundles();
        for(auto const &td_byte : map_td_bytes) {
            spiffeid_TrustDomain td
                = spiffeid_TrustDomainFromString(td_byte.first.c_str(), err);
            if(!(*err)) {
                jwtbundle_Bundle *bundle
                    = jwtbundle_Parse(td, td_byte.second.c_str(), err);
                if(!(*err) && bundle) {
                    jwtbundle_Set_Add(set, bundle);
                }
            }
            spiffeid_TrustDomain_Free(&td);
        }

        return set;
    }
    // null pointer error
    *err = ERR_NULL;
    return NULL;
}

workloadapi_Client *workloadapi_NewClient(err_t *error)
{
    workloadapi_Client *client
        = (workloadapi_Client *) calloc(1, sizeof *client);
    if(!client) {
        *error = ERR_NULL;
        return NULL;
    }
    client->stub = NULL;
    client->address = NULL;
    client->headers = NULL;
    client->context_list = NULL;
    mtx_init(&(client->closed_mutex), mtx_plain);
    cnd_init(&(client->closed_cond));
    mtx_lock(&(client->closed_mutex));
    client->closed = true;
    client->owns_stub = false;
    mtx_unlock(&(client->closed_mutex));
    *error = NO_ERROR;
    return client;
}

err_t workloadapi_Client_Free(workloadapi_Client *client)
{
    if(!client) {
        return ERR_NULL;
    }

    util_string_arr_t_Free(
        client->headers); // null safe. free's all strings in headers.

    util_string_t_Free(client->address);

    mtx_destroy(&(client->closed_mutex));
    cnd_destroy(&(client->closed_cond));

    free(client);
    return NO_ERROR;
}

err_t workloadapi_Client_Connect(workloadapi_Client *client)
{
    if(!client) {
        return ERR_NULL;
    }
    // if client already has a stub, we don't create a new one.
    if(!client->stub) {
        std::shared_ptr<grpc::ChannelInterface> chan = grpc::CreateChannel(
            client->address, grpc::InsecureChannelCredentials());
        if(!chan) {
            return ERR_NULL;
        }
        std::unique_ptr<SpiffeWorkloadAPI::StubInterface> new_stub
            = SpiffeWorkloadAPI::NewStub(chan);
        if(!new_stub) {
            return ERR_NULL_STUB;
        }
        // extends lifetime of pointer to outside this scope
        client->stub = new_stub.release();
        client->owns_stub = true;
    }
    mtx_lock(&(client->closed_mutex));
    client->closed = false;
    mtx_unlock(&(client->closed_mutex));
    return NO_ERROR;
}

err_t workloadapi_Client_Close(workloadapi_Client *client)
{

    if(!client) {
        return ERR_NULL;
    }
    if(!client->stub) {
        return ERR_NULL_STUB; // can't close NULL stub.
    }
    mtx_lock(&(client->closed_mutex));
    if(client->closed) {
        mtx_unlock(&(client->closed_mutex));
        return ERR_CLOSED; // already closed
    }
    client->closed = true;
    if(client->owns_stub) {
        // delete it since grpc new'd it internally and we released it.
        delete((SpiffeWorkloadAPI::Stub *) client->stub);
        client->owns_stub = false;
    }
    for(size_t i = 0, size = arrlenu(client->context_list); i < size; i++) {
        ((grpc::ClientContext *) client->context_list[i])->TryCancel();
    }
    arrfree(client->context_list);

    client->stub = NULL;
    cnd_broadcast(&(client->closed_cond));
    mtx_unlock(&(client->closed_mutex));

    // grpc will free the channel when no stub is using it.
    return NO_ERROR;
}

err_t workloadapi_Client_SetAddress(workloadapi_Client *client,
                                    const char *address)
{
    err_t error = NO_ERROR;
    if(!client) {
        return ERR_NULL;
    }
    // validate address
    UriUriA uri;
    const char *err_pos;
    if(uriParseSingleUriA(&uri, address, &err_pos) != URI_SUCCESS) {
        return ERR_PARSING;
    }

    if(client->address) {
        util_string_t_Free(client->address);
        client->address = NULL;
    }

    client->address = string_new(address);
    if(!client->address) {
        return ERR_CREATE;
    }
    return NO_ERROR;
}

err_t workloadapi_Client_AddHeader(workloadapi_Client *client, const char *key,
                                   const char *value)
{
    if(!client) {
        return ERR_NULL;
    } else {
        arrpush(client->headers, string_new(key));
        arrpush(client->headers, string_new(value));
    }
    return NO_ERROR;
}

err_t workloadapi_Client_SetHeader(workloadapi_Client *client, const char *key,
                                   const char *value)
{
    workloadapi_Client_ClearHeaders(client);
    workloadapi_Client_AddHeader(client, key, value);
    return NO_ERROR;
}

err_t workloadapi_Client_ClearHeaders(workloadapi_Client *client)
{
    util_string_arr_t_Free(client->headers);
    return NO_ERROR;
}

err_t workloadapi_Client_SetStub(workloadapi_Client *client,
                                 workloadapi_Stub stub)
{
    if(!client) {
        return ERR_NULL;
    }
    if(client->owns_stub) {
        // delete it since grpc new'd it internally and we released it.
        delete((SpiffeWorkloadAPI::StubInterface *) client->stub);
        client->stub = NULL;
    }
    client->owns_stub = false;
    client->stub = stub;
    return NO_ERROR;
}

void workloadapi_Client_setDefaultAddressOption(workloadapi_Client *client,
                                                void *not_used)
{
    workloadapi_Client_SetAddress(client, "unix:///tmp/agent.sock");
}

void workloadapi_Client_setDefaultHeaderOption(workloadapi_Client *client,
                                               void *not_used)
{
    workloadapi_Client_SetHeader(client, "workload.spiffe.io", "true");
}

void workloadapi_Client_ApplyOption(workloadapi_Client *client,
                                    workloadapi_ClientOption option)
{
    workloadapi_Client_ApplyOptionWithArg(client, option, NULL);
}

void workloadapi_Client_ApplyOptionWithArg(workloadapi_Client *client,
                                           workloadapi_ClientOption option,
                                           void *arg)
{
    option(client, arg);
}

void workloadapi_Client_defaultOptions(workloadapi_Client *client,
                                       void *not_used)
{
    workloadapi_Client_ApplyOption(client,
                                   workloadapi_Client_setDefaultAddressOption);
    workloadapi_Client_ApplyOption(client,
                                   workloadapi_Client_setDefaultHeaderOption);
}

err_t workloadapi_Client_WatchX509Context(workloadapi_Client *client,
                                          workloadapi_Watcher *watcher)
{
    if(!client)
        return ERR_NULL;
    if(!watcher)
        return ERR_NULL;

    workloadapi_Backoff backoff = workloadapi_NewBackoff({ 1, 0 }, { 30, 0 });

    while(true) {
        err_t err
            = workloadapi_Client_watchX509Context(client, watcher, &backoff);
        workloadapi_Watcher_OnX509ContextWatchError(watcher, err);
        err = workloadapi_Client_HandleWatchError(client, err, &backoff);
        if(err == (int) grpc::CANCELLED
           || err == (int) grpc::INVALID_ARGUMENT) {
            return ERR_INVALID_DATA;
        } else if(err != NO_ERROR) {
            return err;
        }
    }
}

err_t workloadapi_Client_watchX509Context(workloadapi_Client *client,
                                          workloadapi_Watcher *watcher,
                                          workloadapi_Backoff *backoff)
{

    if(!client) {
        return ERR_NULL;
    }
    if(!watcher) {
        return ERR_NULL;
    }
    if(!backoff) {
        return ERR_NULL;
    }

    grpc::ClientContext *ctx = new grpc::ClientContext();

    if(client->headers) {
        for(int i = 0; i < arrlen(client->headers); i += 2)
            ctx->AddMetadata(client->headers[i], client->headers[i + 1]);
    }

    X509SVIDRequest req = X509SVIDRequest(); // empty request
    X509SVIDResponse response;

    // unique_ptr gets freed after it goes out of scope
    std::unique_ptr<grpc::ClientReaderInterface<X509SVIDResponse>> c_reader
        = ((SpiffeWorkloadAPI::StubInterface *) client->stub)
              ->FetchX509SVID(ctx, req); // get response reader
    arrput(client->context_list, (void *) ctx);
    while(true) {

        response.clear_svids();
        response.clear_crl();
        response.clear_federated_bundles();

        bool ok = c_reader->Read(&response);
        if(!ok) {
            auto status = c_reader->Finish();
            if(status.error_code() == (int) grpc::StatusCode::CANCELLED) {
                return ERR_CANCELLED_STATUS;
            }
            if(status.error_code()
               == (int) grpc::StatusCode::INVALID_ARGUMENT) {
                return ERR_INVALID_STATUS;
            }
            return ERR_NO_MESSAGE; // no more messages.
        }
        workloadapi_Backoff_Reset(backoff);
        err_t err = NO_ERROR;
        workloadapi_X509Context *x509context
            = workloadapi_parseX509Context(&response, &err);
        if(err != NO_ERROR) {
            workloadapi_Watcher_OnX509ContextWatchError(watcher, err);
        } else {
            workloadapi_Watcher_OnX509ContextUpdate(watcher, x509context);
            free(x509context);
        }
    }
}

err_t workloadapi_Client_HandleWatchError(workloadapi_Client *client,
                                          err_t error,
                                          workloadapi_Backoff *backoff)
{

    if(error == (int) grpc::StatusCode::CANCELLED) {
        return ERR_CANCELLED_STATUS;
    }
    if(error == (int) grpc::StatusCode::INVALID_ARGUMENT) {
        return ERR_INVALID_STATUS;
    }

    struct timespec retryAfter = workloadapi_Backoff_NextTime(backoff);

    mtx_lock(&(client->closed_mutex));
    if(client->closed) {
        mtx_unlock(&(client->closed_mutex));
        return ERR_CLOSED;
    } else {
        int wait_ret = cnd_timedwait(&(client->closed_cond),
                                     &(client->closed_mutex), &retryAfter);
        if(wait_ret == thrd_timedout) { // waited enough
            mtx_unlock(&(client->closed_mutex));
            return NO_ERROR;
        } else if(wait_ret == thrd_success) { // signaled by closeClient
            mtx_unlock(&(client->closed_mutex));
            return ERR_CLOSING; // ERR_CLOSING == client closing
        } else {
            mtx_unlock(&(client->closed_mutex));
            return ERR_CLOSED;
        }
    }
    return ERR_DEFAULT; /// shouldn't reach this.
}

workloadapi_X509Context *
workloadapi_Client_FetchX509Context(workloadapi_Client *client, err_t *error)
{
    grpc::ClientContext *ctx = new grpc::ClientContext();

    if(client->headers) {
        for(int i = 0; i < arrlen(client->headers); i += 2)
            ctx->AddMetadata(client->headers[i], client->headers[i + 1]);
    }

    X509SVIDRequest req = X509SVIDRequest(); // empty request
    X509SVIDResponse response;

    std::unique_ptr<grpc::ClientReaderInterface<X509SVIDResponse>> c_reader
        = ((SpiffeWorkloadAPI::StubInterface *) client->stub)
              ->FetchX509SVID(ctx, req); // get response reader
    arrput(client->context_list, (void *) ctx);
    bool success = c_reader->Read(&response);
    workloadapi_X509Context *ret = NULL;

    if(success) {
        ret = workloadapi_parseX509Context(&response, error);
        if(*error != NO_ERROR) {
            return NULL;
        }
        return ret;
    } else {
        // could not fetch x509 context
        *error = ERR_BAD_REQUEST;
        return NULL;
    }
}

x509bundle_Set *workloadapi_Client_FetchX509Bundles(workloadapi_Client *client,
                                                    err_t *err)
{
    grpc::ClientContext *ctx = new grpc::ClientContext();

    if(client->headers) {
        for(int i = 0; i < arrlen(client->headers); i += 2)
            ctx->AddMetadata(client->headers[i], client->headers[i + 1]);
    }

    X509SVIDRequest req = X509SVIDRequest(); // empty request
    X509SVIDResponse response;

    std::unique_ptr<grpc::ClientReaderInterface<X509SVIDResponse>> c_reader
        = ((SpiffeWorkloadAPI::StubInterface *) client->stub)
              ->FetchX509SVID(ctx, req); // get response reader
    arrput(client->context_list, (void *) ctx);
    bool success = c_reader->Read(&response);
    x509bundle_Set *ret_set = NULL;
    if(success) {
        ret_set = workloadapi_parseX509Bundles(&response, err);
        if(*err != NO_ERROR) {
            return NULL;
        }
        return ret_set;
    } else {
        // could not fetch x509 bundles
        *err = ERR_BAD_REQUEST;
        return NULL;
    }
}

x509svid_SVID **workloadapi_Client_FetchX509SVIDs(workloadapi_Client *client,
                                                  err_t *err)
{
    grpc::ClientContext *ctx = new grpc::ClientContext();

    if(client->headers) {
        for(int i = 0; i < arrlen(client->headers); i += 2)
            ctx->AddMetadata(client->headers[i], client->headers[i + 1]);
    }

    X509SVIDRequest req = X509SVIDRequest(); // empty request
    X509SVIDResponse response;

    std::unique_ptr<grpc::ClientReaderInterface<X509SVIDResponse>> c_reader
        = ((SpiffeWorkloadAPI::StubInterface *) client->stub)
              ->FetchX509SVID(ctx, req); // get response reader
    arrput(client->context_list, (void *) ctx);
    bool success = c_reader->Read(&response);
    x509svid_SVID **ret_svids = NULL;
    if(success) {
        ret_svids = workloadapi_parseX509SVIDs(&response, false, err);
        if(*err != NO_ERROR) {
            return NULL;
        }
        return ret_svids;
    } else {
        // could not parse x509 svids
        *err = ERR_BAD_REQUEST;
        return NULL;
    }
}

x509svid_SVID *workloadapi_Client_FetchX509SVID(workloadapi_Client *client,
                                                err_t *err)
{
    grpc::ClientContext *ctx = new grpc::ClientContext();

    if(client->headers) {
        for(int i = 0; i < arrlen(client->headers); i += 2)
            ctx->AddMetadata(client->headers[i], client->headers[i + 1]);
    }

    X509SVIDRequest req = X509SVIDRequest(); // empty request
    X509SVIDResponse response;

    std::unique_ptr<grpc::ClientReaderInterface<X509SVIDResponse>> c_reader
        = ((SpiffeWorkloadAPI::StubInterface *) client->stub)
              ->FetchX509SVID(ctx, req); // get response reader
    arrput(client->context_list, (void *) ctx);
    bool success = c_reader->Read(&response);
    x509svid_SVID **svids = NULL;
    if(success) {
        svids = workloadapi_parseX509SVIDs(&response, true, err);
        if(*err != NO_ERROR) {
            return NULL;
        }
        if(arrlen(svids) == 0) {
            return NULL; // Should never happen
        }
        x509svid_SVID *ret_svid = svids[0];
        for(size_t i = 1, size = arrlenu(svids); i < size; ++i) {
            x509svid_SVID_Free(svids[i]);
        }
        arrfree(svids);  // free outer array
        return ret_svid; // no response -> no bundle
    } else {
        // could not fetch x509 svid;
        *err = ERR_BAD_REQUEST;
        return NULL;
    }
}

jwtsvid_SVID *workloadapi_Client_FetchJWTSVID(workloadapi_Client *client,
                                              jwtsvid_Params *params,
                                              err_t *err)
{
    grpc::ClientContext *ctx = new grpc::ClientContext();

    if(client->headers) {
        for(int i = 0; i < arrlen(client->headers); i += 2)
            ctx->AddMetadata(client->headers[i], client->headers[i + 1]);
    }

    JWTSVIDRequest req;

    // set spiffe id
    if(!spiffeid_ID_IsZero(params->subject)) {
        string_t id = spiffeid_ID_String(params->subject);
        req.set_spiffe_id(id);
        arrfree(id);
    }

    // set audiences
    if(params->audience) {
        req.add_audience(params->audience);
        for(size_t i = 0, size = arrlenu(params->extra_audiences); i < size;
            ++i) {
            req.add_audience(params->extra_audiences[i]);
        }
    }

    JWTSVIDResponse resp;
    grpc::Status status = ((SpiffeWorkloadAPI::StubInterface *) client->stub)
                              ->FetchJWTSVID(ctx, req, &resp);

    if(status.ok()) {
        // parse response
        return workloadapi_parseJWTSVID(&resp, params, err);
    } else {
        // could not fetch jwt svid
        *err = ERR_BAD_REQUEST;
        return NULL;
    }
}

jwtbundle_Set *workloadapi_Client_FetchJWTBundles(workloadapi_Client *client,
                                                  err_t *err)
{
    grpc::ClientContext ctx;

    if(client->headers) {
        for(int i = 0; i < arrlen(client->headers); i += 2)
            ctx.AddMetadata(client->headers[i], client->headers[i + 1]);
    }

    JWTBundlesRequest req;
    std::unique_ptr<grpc::ClientReaderInterface<JWTBundlesResponse>> c_reader
        = ((SpiffeWorkloadAPI::StubInterface *) client->stub)
              ->FetchJWTBundles(&ctx, req);

    JWTBundlesResponse resp;
    bool success = c_reader->Read(&resp);
    if(success) {
        // parse response
        return workloadapi_parseJWTBundles(&resp, err);
    } else {
        // could not fetch jwt bundles
        *err = ERR_BAD_REQUEST;
        return NULL;
    }
}

jwtsvid_SVID *workloadapi_Client_ValidateJWTSVID(workloadapi_Client *client,
                                                 char *token, char *audience,
                                                 err_t *err)
{
    grpc::ClientContext ctx;

    ValidateJWTSVIDRequest req;
    req.set_svid(token);
    req.set_audience(audience);

    ValidateJWTSVIDResponse resp;
    grpc::Status status = ((SpiffeWorkloadAPI::StubInterface *) client->stub)
                              ->ValidateJWTSVID(&ctx, req, &resp);

    if(status.ok()) {
        // parse response
        string_arr_t audiences_array = NULL;
        arrput(audiences_array, audience);
        jwtsvid_SVID *svid
            = jwtsvid_ParseInsecure(token, audiences_array, err);
        arrfree(audiences_array);

        return svid;
    } else {
        // could not validate jwt svid
        *err = ERR_BAD_REQUEST;
        return NULL;
    }
}

err_t workloadapi_Client_WatchJWTBundles(workloadapi_Client *client,
                                         workloadapi_JWTWatcher *watcher)
{
    if(!client)
        return ERR_NULL;
    if(!watcher)
        return ERR_NULL;
    workloadapi_Backoff backoff = workloadapi_NewBackoff({ 1, 0 }, { 30, 0 });
    while(true) {
        err_t err
            = workloadapi_Client_watchJWTBundles(client, watcher, &backoff);
        workloadapi_JWTWatcher_OnJWTBundlesWatchError(watcher, err);
        err = workloadapi_Client_HandleWatchError(client, err, &backoff);

        if(err == (int) grpc::CANCELLED
           || err == (int) grpc::INVALID_ARGUMENT) {
            return ERR_INVALID_DATA;
        } else if(err != NO_ERROR) {
            return err;
        }
    }
}

err_t workloadapi_Client_watchJWTBundles(workloadapi_Client *client,
                                         workloadapi_JWTWatcher *watcher,
                                         workloadapi_Backoff *backoff)
{
    if(!client || !watcher || !backoff) {
        return ERR_NULL;
    }
    grpc::ClientContext *ctx = new grpc::ClientContext();
    if(client->headers) {
        for(int i = 0; i < arrlen(client->headers); i += 2)
            ctx->AddMetadata(client->headers[i], client->headers[i + 1]);
    }
    JWTBundlesRequest req;
    JWTBundlesResponse resp;
    // unique_ptr gets freed after it goes out of scope
    std::unique_ptr<grpc::ClientReaderInterface<JWTBundlesResponse>> c_reader
        = ((SpiffeWorkloadAPI::StubInterface *) client->stub)
              ->FetchJWTBundles(ctx, req); // get response reader
    arrput(client->context_list, (void *) ctx);
    while(true) {
        bool ok = c_reader->Read(&resp);
        if(!ok) {
            auto status = c_reader->Finish();
            if(status.error_code() == (int) grpc::StatusCode::CANCELLED) {
                return ERR_CANCELLED_STATUS;
            }
            if(status.error_code()
               == (int) grpc::StatusCode::INVALID_ARGUMENT) {
                return ERR_INVALID_STATUS;
            }
            return ERR_NO_MESSAGE; // no more messages.
        }
        workloadapi_Backoff_Reset(backoff);
        err_t err = NO_ERROR;
        jwtbundle_Set *set = workloadapi_parseJWTBundles(&resp, &err);
        if(err != NO_ERROR) {
            workloadapi_JWTWatcher_OnJWTBundlesWatchError(watcher, err);
        } else {
            workloadapi_JWTWatcher_OnJWTBundlesUpdate(watcher, set);
            jwtbundle_Set_Free(set);
        }
    }
}
