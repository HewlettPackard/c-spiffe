/*
 * Filename: c-spiffe/requestor/requestor.cpp
 * Path: c-spiffe/requestor
 * Created Date: Monday, December 21nd 2020, 10:32:38 am
 * Author: Rodrigo Lopes (rlc2@cesar.org.br)
 *
 * Copyright (c) 2020 CESAR
 */

#include "requestor.h"
#include "../../bundle/x509bundle/src/bundle.h"
#include "../../bundle/x509bundle/src/set.h"
#include "../../svid/x509svid/src/svid.h"
#include "client.h"
#include "workload.grpc.pb.h"
#include "workload.pb.h"
#include <cstring>
#include <grpc/grpc.h>
#include <grpcpp/grpcpp.h>

using grpc::Channel;
using grpc::ClientContext;
using grpc::ClientReader;
using grpc::Status;

// New requestor
// for testing, RequestorInitWithStub should used directly
workloadapi_Requestor *workloadapi_RequestorInit(const char *address)
{
    return workloadapi_RequestorInitWithStub(address, NULL);
}

workloadapi_Requestor *workloadapi_RequestorInitWithStub(const char *address,
                                                         stub_ptr stub)
{
    if(!address)
        return NULL;
    workloadapi_Requestor *req = (workloadapi_Requestor *) malloc(sizeof *req);
    req->address = string_new(address);

    if(!stub) {
        std::shared_ptr<Channel> chan = grpc::CreateChannel(
            req->address, grpc::InsecureChannelCredentials());
        std::unique_ptr<SpiffeWorkloadAPI::StubInterface> new_stub
            = SpiffeWorkloadAPI::NewStub(chan);
        req->stub = new_stub.release();
    } else {
        req->stub = stub;
    }

    return req;
}

void workloadapi_RequestorFree(workloadapi_Requestor *requestor)
{
    if(requestor) {
        arrfree(requestor->address);
        // TODO Should we free the stub?
        // if(requestor->stub)
        // {
        //     free(requestor->stub;
        // }
        free(requestor);
    }
}

// Fetch first entitled SVID.
x509svid_SVID *
workloadapi_FetchDefaultX509SVID(workloadapi_Requestor *requestor)
{
    ClientContext ctx;
    ctx.AddMetadata("workload.spiffe.io", "true"); // mandatory

    X509SVIDRequest req = X509SVIDRequest(); // empty request
    X509SVIDResponse response;

    std::unique_ptr<grpc::ClientReaderInterface<X509SVIDResponse>> c_reader
        = ((SpiffeWorkloadAPI::StubInterface *) requestor->stub)
              ->FetchX509SVID(&ctx, req); // get response reader

    while(c_reader->Read(&response)) // while there are messages
    {
        x509svid_SVID *x509svid = NULL;
        auto ids = response.svids(); // all SVID's the workload is entitled to.
        for(auto &&id : ids) {
            err_t err;
            // assemble SVID from response.
            x509svid = x509svid_ParseRaw((byte *) id.x509_svid().data(),
                                         id.x509_svid().length(),
                                         (byte *) id.x509_svid_key().data(),
                                         id.x509_svid_key().length(), &err);
            if(err)
                return NULL;
            else
                return x509svid; // first SVID found.
        }
        return x509svid; // no SVID in response
    }
    return NULL; // no response -> no SVID
}

x509bundle_Set *workloadapi_FetchX509Bundles(workloadapi_Requestor *requestor)
{
    ClientContext ctx;
    ctx.AddMetadata("workload.spiffe.io", "true"); // mandatory

    X509SVIDRequest req = X509SVIDRequest(); // empty request
    X509SVIDResponse response;

    std::unique_ptr<grpc::ClientReaderInterface<X509SVIDResponse>> c_reader
        = ((SpiffeWorkloadAPI::StubInterface *) requestor->stub)
              ->FetchX509SVID(&ctx, req); // get response reader

    bool success = c_reader->Read(&response);
    x509bundle_Set *ret_set = NULL;
    err_t error;
    if(success) {
        ret_set = workloadapi_parseX509Bundles(&response, &error);
        // TODO check error
    }

    return ret_set; // no response -> no bundle
}
