
#include "../../internal/x509util/src/util.h"

#include "../../bundle/x509bundle/src/bundle.h"
#include "../../bundle/x509bundle/src/set.h"
#include "../../svid/x509svid/src/svid.h"
#include "client.h"
#include "workload.grpc.pb.h"
#include "workload.pb.h"
#include <grpc/grpc.h>
#include <grpcpp/grpcpp.h>

x509bundle_Bundle *workloadapi_parseX509Bundle(string_t id,
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
            string_t td_str = string_new(id.spiffe_id().c_str());
            x509bundle_Bundle *b = workloadapi_parseX509Bundle(
                td_str, reinterpret_cast<const byte *>(id.bundle().data()),
                id.bundle().length(), &err);
            arrfree(td_str);
            x509bundle_Set_Add(set, b);
        }

        auto map_td_bytes = rep->federated_bundles();
        for(auto const &td_byte : map_td_bytes) {
            err_t err;
            string_t td_str = string_new(td_byte.first.c_str());
            x509bundle_Bundle *b = workloadapi_parseX509Bundle(
                td_str, reinterpret_cast<const byte *>(td_byte.second.data()),
                td_byte.second.length(), &err);
            arrfree(td_str);
            x509bundle_Set_Add(set, b);
        }

        return set;
    }
    // null pointer error
    *err = ERROR1;
    return NULL;
}

x509svid_SVID **workloadapi_parseX509SVIDs(X509SVIDResponse *resp,
                                           bool firstOnly, err_t *err)
{
    if(!resp) {
        *err = ERROR2;
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
            x509svid_SVID_Free(svids[i], true);
        }
        arrfree(svids);
        return NULL;
    }
    *err = NO_ERROR;
    workloadapi_X509Context *cntx
        = (workloadapi_X509Context *) calloc(1, sizeof *cntx);
    if(!cntx) {
        for(int i = 0; i < arrlen(svids); i++) {
            x509svid_SVID_Free(svids[i], true);
        }
        arrfree(svids);
        x509bundle_Set_Free(bundles);
        *err = ERROR5;
        return NULL;
    }
    cntx->bundles = bundles;
    cntx->svids = svids;

    return cntx;
}

workloadapi_Client *workloadapi_NewClient(err_t *error)
{
    workloadapi_Client *client
        = (workloadapi_Client *) calloc(1, sizeof *client);
    if(!client) {
        *error = ERROR1;
        return NULL;
    }
    client->stub = NULL;
    client->address = NULL;
    client->headers = NULL;
    mtx_init(&(client->closedMutex), mtx_plain);
    cnd_init(&(client->closedCond));
    mtx_lock(&(client->closedMutex));
    client->closed = true;
    client->ownsStub = false;
    mtx_unlock(&(client->closedMutex));
    *error = NO_ERROR;
    return client;
}

err_t workloadapi_Client_Free(workloadapi_Client *client)
{
    if(!client) {
        return ERROR1;
    }

    util_string_arr_t_Free(
        client->headers); // null safe. free's all strings in headers.

    util_string_t_Free(client->address);

    mtx_destroy(&(client->closedMutex));
    cnd_destroy(&(client->closedCond));

    free(client);
    return NO_ERROR;
}

err_t workloadapi_Client_Connect(workloadapi_Client *client)
{
    if(!client) {
        return ERROR1;
    }
    // if client already has a stub, we don't create a new one.
    if(!client->stub) {
        std::shared_ptr<grpc::ChannelInterface> chan = grpc::CreateChannel(
            client->address, grpc::InsecureChannelCredentials());
        if(!chan) {
            return ERROR2;
        }
        std::unique_ptr<SpiffeWorkloadAPI::StubInterface> new_stub
            = SpiffeWorkloadAPI::NewStub(chan);
        if(!new_stub) {
            return ERROR3;
        }
        // extends lifetime of pointer to outside this scope
        client->stub = new_stub.release();
        client->ownsStub = true;
    }
    mtx_lock(&(client->closedMutex));
    client->closed = false;
    mtx_unlock(&(client->closedMutex));
    return NO_ERROR;
}

err_t workloadapi_Client_Close(workloadapi_Client *client)
{

    if(!client) {
        return ERROR1;
    }
    if(!client->stub) {
        return ERROR3; // can't close NULL stub.
    }
    mtx_lock(&(client->closedMutex));
    if(client->closed) {
        mtx_unlock(&(client->closedMutex));
        return ERROR2; // already closed
    }
    client->closed = true;
    if(client->ownsStub) {
        // delete it since grpc new'd it internally and we released it.
        delete((SpiffeWorkloadAPI::Stub *) client->stub);
        client->ownsStub = false;
    }
    client->stub = NULL;
    cnd_broadcast(&(client->closedCond));
    mtx_unlock(&(client->closedMutex));

    // grpc will free the channel when no stub is using it.
    return NO_ERROR;
}

err_t workloadapi_Client_SetAddress(workloadapi_Client *client,
                                    const char *address)
{
    if(!client) {
        return ERROR1;
    }
    if(client->address) {
        util_string_t_Free(client->address);
        client->address = NULL;
    }
    /// TODO: validate address as URI
    client->address = string_new(address);
    return NO_ERROR;
}

err_t workloadapi_Client_AddHeader(workloadapi_Client *client, const char *key,
                                   const char *value)
{
    if(!client) {
        return ERROR1;
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
        return ERROR1;
    }
    if(client->ownsStub) {
        // delete it since grpc new'd it internally and we released it.
        delete((SpiffeWorkloadAPI::StubInterface *) client->stub);
        client->stub = NULL;
    }
    client->ownsStub = false;
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

    /// TODO: logger?
    /// TODO: dialOptions?
}

err_t workloadapi_Client_WatchX509Context(workloadapi_Client *client,
                                          workloadapi_Watcher *watcher)
{
    if(!client)
        return ERROR1;
    if(!watcher)
        return ERROR2;

    workloadapi_Backoff backoff = workloadapi_NewBackoff({ 1, 0 }, { 30, 0 });

    while(true) {
        err_t err
            = workloadapi_Client_watchX509Context(client, watcher, &backoff);
        workloadapi_Watcher_OnX509ContextWatchError(watcher, err);
        err = workloadapi_Client_HandleWatchError(client, err, &backoff);
        // TODO: check error and reuse backoff if not cancelled
        if(err == grpc::CANCELLED || err == grpc::INVALID_ARGUMENT) {
            return err;
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
        return ERROR2;
    }
    if(!watcher) {
        return ERROR2;
    }
    if(!backoff) {
        return ERROR2;
    }

    /// TODO: Logger?

    grpc::ClientContext ctx;

    if(client->headers) {
        for(int i = 0; i < arrlen(client->headers); i += 2)
            ctx.AddMetadata(client->headers[i], client->headers[i + 1]);
    }

    X509SVIDRequest req = X509SVIDRequest(); // empty request
    X509SVIDResponse response;

    // unique_ptr gets freed after it goes out of scope
    std::unique_ptr<grpc::ClientReaderInterface<X509SVIDResponse>> c_reader
        = ((SpiffeWorkloadAPI::StubInterface *) client->stub)
              ->FetchX509SVID(&ctx, req); // get response reader
    while(true) {

        response.clear_svids();
        response.clear_crl();
        response.clear_federated_bundles();

        bool ok = c_reader->Read(&response);
        if(!ok) {
            auto status = c_reader->Finish();
            if(status.error_code() == grpc::StatusCode::CANCELLED) {
                return ERROR1;
            }
            if(status.error_code() == grpc::StatusCode::INVALID_ARGUMENT) {
                /// TODO: Logger
                return ERROR3;
            }
            return ERROR4; // no more messages.
        }
        workloadapi_Backoff_Reset(backoff);
        err_t err = NO_ERROR;
        workloadapi_X509Context *x509context
            = workloadapi_parseX509Context(&response, &err);
        if(err != NO_ERROR) {
            /// TODO: log parse error
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

    if(error == grpc::StatusCode::CANCELLED) {
        return error;
    }
    if(error == grpc::StatusCode::INVALID_ARGUMENT) {
        /// TODO: Logger
        return error;
    }

    /// TODO: Log
    struct timespec retryAfter = workloadapi_Backoff_NextTime(backoff);

    mtx_lock(&(client->closedMutex));
    if(client->closed) {
        mtx_unlock(&(client->closedMutex));
        return ERROR4;
    } else {
        int wait_ret = cnd_timedwait(&(client->closedCond),
                                     &(client->closedMutex), &retryAfter);
        if(wait_ret == thrd_timedout) { // waited enough
            mtx_unlock(&(client->closedMutex));
            return NO_ERROR;
        } else if(wait_ret == thrd_success) { // signaled by closeClient
            mtx_unlock(&(client->closedMutex));
            return ERROR5;
        } else {
            mtx_unlock(&(client->closedMutex));
            return ERROR6;
        }
    }
    return ERROR2; /// shouldn't reach this.
}

workloadapi_X509Context *
workloadapi_Client_FetchX509Context(workloadapi_Client *client, err_t *error)
{
    grpc::ClientContext ctx;

    if(client->headers) {
        for(int i = 0; i < arrlen(client->headers); i += 2)
            ctx.AddMetadata(client->headers[i], client->headers[i + 1]);
    }

    X509SVIDRequest req = X509SVIDRequest(); // empty request
    X509SVIDResponse response;

    std::unique_ptr<grpc::ClientReaderInterface<X509SVIDResponse>> c_reader
        = ((SpiffeWorkloadAPI::StubInterface *) client->stub)
              ->FetchX509SVID(&ctx, req); // get response reader

    bool success = c_reader->Read(&response);
    workloadapi_X509Context *ret = NULL;

    if(success) {
        ret = workloadapi_parseX509Context(&response, error);
        if(*error != NO_ERROR) {
            return NULL;
        }
    }

    return ret; // no response -> no bundle
}

x509bundle_Set *workloadapi_Client_FetchX509Bundles(workloadapi_Client *client,
                                                    err_t *err)
{
    grpc::ClientContext ctx;

    if(client->headers) {
        for(int i = 0; i < arrlen(client->headers); i += 2)
            ctx.AddMetadata(client->headers[i], client->headers[i + 1]);
    }

    X509SVIDRequest req = X509SVIDRequest(); // empty request
    X509SVIDResponse response;

    std::unique_ptr<grpc::ClientReaderInterface<X509SVIDResponse>> c_reader
        = ((SpiffeWorkloadAPI::StubInterface *) client->stub)
              ->FetchX509SVID(&ctx, req); // get response reader

    bool success = c_reader->Read(&response);
    x509bundle_Set *ret_set = NULL;
    if(success) {
        ret_set = workloadapi_parseX509Bundles(&response, err);
        if(*err != NO_ERROR) {
            return NULL;
        }
    }

    return ret_set; // no response -> no bundle
}

x509svid_SVID **workloadapi_Client_FetchX509SVIDs(workloadapi_Client *client,
                                                  err_t *err)
{
    grpc::ClientContext ctx;

    if(client->headers) {
        for(int i = 0; i < arrlen(client->headers); i += 2)
            ctx.AddMetadata(client->headers[i], client->headers[i + 1]);
    }

    X509SVIDRequest req = X509SVIDRequest(); // empty request
    X509SVIDResponse response;

    std::unique_ptr<grpc::ClientReaderInterface<X509SVIDResponse>> c_reader
        = ((SpiffeWorkloadAPI::StubInterface *) client->stub)
              ->FetchX509SVID(&ctx, req); // get response reader

    bool success = c_reader->Read(&response);
    x509svid_SVID **ret_svids = NULL;
    if(success) {
        ret_svids = workloadapi_parseX509SVIDs(&response, false, err);
        if(*err != NO_ERROR) {
            return NULL;
        }
    }

    return ret_svids; // no response -> no bundle
}

x509svid_SVID *workloadapi_Client_FetchX509SVID(workloadapi_Client *client,
                                                err_t *err)
{
    grpc::ClientContext ctx;

    if(client->headers) {
        for(int i = 0; i < arrlen(client->headers); i += 2)
            ctx.AddMetadata(client->headers[i], client->headers[i + 1]);
    }

    X509SVIDRequest req = X509SVIDRequest(); // empty request
    X509SVIDResponse response;

    std::unique_ptr<grpc::ClientReaderInterface<X509SVIDResponse>> c_reader
        = ((SpiffeWorkloadAPI::StubInterface *) client->stub)
              ->FetchX509SVID(&ctx, req); // get response reader

    bool success = c_reader->Read(&response);
    x509svid_SVID **svids = NULL;
    if(success) {
        svids = workloadapi_parseX509SVIDs(&response, true, err);
        if(*err != NO_ERROR) {
            return NULL;
        }
    }
    if(arrlen(svids) == 0)
        return NULL; // Should never happen
    x509svid_SVID *ret_svid = svids[0];
    arrfree(svids);  // free outer array
    return ret_svid; // no response -> no bundle
}

jwtsvid_SVID *workloadapi_parseJWTSVID(const JWTSVIDResponse *resp,
                                       jwtsvid_Params *params, err_t *err)
{
    if(resp) {
        // insert audience at the beginning of the array
        arrins(params->extraAudiences, 0, params->audience);
        // for memory safety
        params->audience = NULL;

        auto id = resp->svids()[0];
        string_t token = string_new(id.svid().c_str());
        jwtsvid_SVID *svid
            = jwtsvid_ParseInsecure(token, params->extraAudiences, err);
        arrfree(token);

        return svid;
    }
    // null pointer error
    *err = ERROR1;
    return NULL;
}

jwtbundle_Set *workloadapi_parseJWTBundles(const JWTBundlesResponse *resp,
                                           err_t *err)
{
    if(resp) {
        jwtbundle_Set *set = jwtbundle_NewSet(0);

        auto map_td_bytes = resp->bundles();
        for(auto const &td_byte : map_td_bytes) {
            string_t td_str = string_new(td_byte.first.c_str());
            spiffeid_TrustDomain td
                = spiffeid_TrustDomainFromString(td_str, err);
            if(!(*err)) {
                jwtbundle_Bundle *bundle
                    = jwtbundle_Parse(td, td_byte.second.c_str(), err);
                if(!(*err) && bundle) {
                    jwtbundle_Set_Add(set, bundle);
                }
            }
            arrfree(td_str);
            spiffeid_TrustDomain_Free(&td);
        }

        return set;
    }
    // null pointer error
    *err = ERROR1;
    return NULL;
}
