/*
 * Filename: c-spiffe/requestor/requestor.cpp
 * Path: c-spiffe/requestor
 * Created Date: Monday, December 21nd 2020, 10:32:38 am
 * Author: Rodrigo Lopes (rlc2@cesar.org.br)
 * 
 * Copyright (c) 2020 CESAR
 */

#include <grpcpp/grpcpp.h>
#include <stdio.h>
#include "workload.pb.h"
#include "workload.grpc.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::ClientReader;
using grpc::Status;

int main(int argc, char const *argv[])
{
    std::shared_ptr<Channel> chan = grpc::CreateChannel("unix:///tmp/agent.sock",grpc::InsecureChannelCredentials());
    
    std::unique_ptr<SpiffeWorkloadAPI::Stub> stub = SpiffeWorkloadAPI::NewStub(chan);
    ClientContext ctx;
    
    X509SVIDRequest req = X509SVIDRequest();
    X509SVIDResponse response;
    
    auto c_reader = stub->FetchX509SVID(&ctx,req);
    
    int a;

    while( ! (a = c_reader->Read(&response))){
        auto ids = response.svids();
        for (auto &&id : ids)
        {
            printf("SPIFFE ID:\n%s\n",id.spiffe_id());
            printf("SVID:\n%s\n",id.x509_svid());
            printf("KEY:\n%s\n",id.x509_svid_key());
        }
    }
    
    return 0;
}
