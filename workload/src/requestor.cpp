/*
 * Filename: c-spiffe/requestor/requestor.cpp
 * Path: c-spiffe/requestor
 * Created Date: Monday, December 21nd 2020, 10:32:38 am
 * Author: Rodrigo Lopes (rlc2@cesar.org.br)
 * 
 * Copyright (c) 2020 CESAR
 */

#include "requestor.h"
#include <grpc/grpc.h>
#include <grpcpp/grpcpp.h>
#include <stdio.h>
#include "workload.pb.h"
#include "workload.grpc.pb.h"
#include "../../svid/x509svid/src/svid.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::ClientReader;
using grpc::Status;

x509svid_SVID* fetch_SVID_CPP(){
    std::shared_ptr<Channel> chan = grpc::CreateChannel("unix:///tmp/agent.sock",grpc::InsecureChannelCredentials());
    auto stub = SpiffeWorkloadAPI::NewStub(chan);
    ClientContext ctx;
    ctx.AddMetadata("workload.spiffe.io","true");

    X509SVIDRequest req = X509SVIDRequest();
    X509SVIDResponse response;
    
    auto c_reader = stub->FetchX509SVID(&ctx,req);
    
    while (c_reader->Read(&response)){
        printf("got response:\n");
        x509svid_SVID* x509svid = NULL;
        auto ids = response.svids();
        for (auto &&id : ids)
        {  
            printf("SPIFFE ID:\n%s\n",id.spiffe_id());
            printf("SVID:\n%s\n",id.x509_svid());
            printf("KEY:\n%s\n",id.x509_svid_key());
            err_t err;
            
            x509svid = x509svid_Parse((byte*) id.x509_svid().data(),(byte*) id.x509_svid_key().data(),&err);
            
        }
        return x509svid;
    }
    return NULL;
}

extern "C"
{
    x509svid_SVID* fetch_SVID() {
        return fetch_SVID_CPP();
    }
}
