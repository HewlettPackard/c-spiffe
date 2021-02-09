#include "client.h"
#include "../../internal/x509util/src/util.h"

#include <grpc/grpc.h>
#include <grpcpp/grpcpp.h>
#include "workload.pb.h"
#include "workload.grpc.pb.h"
#include "../../svid/x509svid/src/svid.h"
#include "../../bundle/x509bundle/src/bundle.h"
#include "../../bundle/x509bundle/src/set.h"

x509bundle_Set *workloadapi_parseX509Bundles(const X509SVIDResponse *rep, err_t *err)
{
    if (rep)
    {
        x509bundle_Set *set = x509bundle_NewSet(0);

        auto ids = rep->svids();
        for (auto &&id : ids)
        {
            err_t err;
            string_t td_str = string_new(id.spiffe_id().c_str());
            x509bundle_Bundle *b = workloadapi_parseX509Bundle(
                td_str,
                reinterpret_cast<const byte *>(id.bundle().data()),
                id.bundle().length(),
                &err);
            arrfree(td_str);
            x509bundle_Set_Add(set, b);
        }

        auto map_td_bytes = rep->federated_bundles();
        for (auto const &td_byte : map_td_bytes)
        {
            err_t err;
            string_t td_str = string_new(td_byte.first.c_str());
            x509bundle_Bundle *b = workloadapi_parseX509Bundle(
                td_str,
                reinterpret_cast<const byte *>(td_byte.second.data()),
                td_byte.second.length(),
                &err);
            arrfree(td_str);
            x509bundle_Set_Add(set, b);
        }

        return set;
    }
    //null pointer error
    *err = ERROR1;
    return NULL;
}

x509bundle_Bundle *workloadapi_parseX509Bundle(string_t id, const byte *bundle_bytes, const size_t len, err_t *err)
{
    x509bundle_Bundle *bundle = NULL;

    if (id && bundle_bytes)
    {
        spiffeid_TrustDomain td = spiffeid_TrustDomainFromString(id, err);

        if (!(*err))
        {
            X509 **certs = x509util_ParseCertificates(bundle_bytes, len, err);

            if (!(*err) && arrlenu(certs) > 0)
            {
                bundle = x509bundle_FromX509Authorities(td, certs);
            }
        }

        spiffeid_TrustDomain_Free(&td, false);
    }

    return bundle;
}

workloadapi_Client *workloadapi_NewClient(err_t *error)
{
    workloadapi_Client *client = (workloadapi_Client *)calloc(1, sizeof *client);
    if (!client)
    {
        *error = ERROR1;
        return NULL;
    }
    client->stub = NULL;
    client->address = NULL;
    client->headers = NULL;
    client->closed = true;
    *error = NO_ERROR;
    return client;
}

err_t workloadapi_FreeClient(workloadapi_Client *client)
{
    if (!client)
    {
        return ERROR1;
    }

    util_string_arr_t_Free(client->headers); //null safe. free's all strings in headers.
    client->headers = NULL;                  //sanity, shouldn't matter after we free everything else

    util_string_t_Free(client->address);
    client->address = NULL;

    free(client);
    return NO_ERROR;
}

err_t workloadapi_ConnectClient(workloadapi_Client *client)
{
    if (!client)
    {
        return ERROR1;
    }
    if (!client->stub) //if client already has a stub, we don't create a new one.
    {
        std::shared_ptr<grpc::ChannelInterface> chan = grpc::CreateChannel(client->address, grpc::InsecureChannelCredentials());
        if (!chan)
        {
            return ERROR2;
        }
        std::unique_ptr<SpiffeWorkloadAPI::StubInterface> new_stub = SpiffeWorkloadAPI::NewStub(chan);
        if (!new_stub)
        {
            return ERROR3;
        }
        client->stub = new_stub.release(); //extends lifetime of pointer to outside this scope
    }
    client->closed = false;
    return NO_ERROR;
}

err_t workloadapi_CloseClient(workloadapi_Client *client)
{
    if (!client)
    {
        return ERROR1;
    }
    if (client->closed)
    {
        return ERROR2; //already closed
    }
    if (!client->stub)
    {
        return ERROR3; //can't close NULL stub.
    }
    delete ((SpiffeWorkloadAPI::StubInterface *)client->stub); //delete it since grpc new'd it internally and we released it.
    client->stub = NULL;
    //grpc will free the channel when no stub is using it.
    client->closed = true;
}

err_t workloadapi_setClientAddress(workloadapi_Client *client, const char *address)
{
    if (!client)
    {
        return ERROR1;
    }
    if (client->address)
    {
        util_string_t_Free(client->address);
        client->address = NULL;
    }
    ///TODO: validate address as URI
    client->address = string_new(address);
}

err_t workloadapi_addClientHeader(workloadapi_Client *client, const char *key, const char *value)
{
    if (!client)
    {
        return ERROR1;
    }
    else
    {
        arrpush(client->headers, string_new(key));
        arrpush(client->headers, string_new(value));
    }
    return NO_ERROR;
}

err_t workloadapi_setClientHeader(workloadapi_Client *client, const char *key, const char *value)
{
    workloadapi_clearClientHeaders(client);
    workloadapi_addClientHeader(client, key, value);
}

err_t workloadapi_clearClientHeaders(workloadapi_Client *client)
{
    util_string_arr_t_Free(client->headers);
}

err_t workloadapi_setClientStub(workloadapi_Client* client, stub_ptr stub){
    if(!client){
        return ERROR1;
    }
    ///TODO: free previous stub if set? error out?
    // if(client->stub){
    //     delete ((SpiffeWorkloadAPI::StubInterface *)client->stub); //delete it since grpc new'd it internally and we released it.
    //     client->stub = NULL;//sanity?
    // }
    client->stub = stub;
    return NO_ERROR;
}

void setDefaultClientAddressOption(workloadapi_Client *client, void *not_used)
{
    workloadapi_setClientAddress(client, "unix:///var/agent.sock");
}

void setDefaultClientHeaderOption(workloadapi_Client *client, void *not_used)
{
    workloadapi_setClientHeader(client, "workload.spiffe.io", "true");
}

void workloadapi_applyClientOption(workloadapi_Client *client, workloadapi_ClientOption option)
{
    workloadapi_applyClientOptionWithArg(client, option, NULL);
}

void workloadapi_applyClientOptionWithArg(workloadapi_Client *client, workloadapi_ClientOption option, void *arg)
{
    option(client, arg);
}

void workloadapi_defaultClientOptions(workloadapi_Client *client, void *not_used)
{
    workloadapi_applyClientOption(client, setDefaultClientAddressOption);
    workloadapi_applyClientOption(client, setDefaultClientHeaderOption);

    ///TODO: logger?
    ///TODO: dialOptions?
}

err_t workloadapi_WatchX509Context(workloadapi_Client* client, workloadapi_Watcher* watcher){

    Backoff backoff = newBackoff(SECOND,{30,0});

    while(true){
        err_t err = workloadapi_watchX509Context(client,watcher,&backoff);
        workloadapi_Watcher_OnX509ContextWatchError(watcher,err);
        err = workloadapi_handleWatchError(client,err,&backoff);
        if(err != NO_ERROR){
            return err;
        }
    }
}

