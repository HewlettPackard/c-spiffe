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
#include "workload.pb.h"
#include "workload.grpc.pb.h"
#include "../../svid/x509svid/src/svid.h"
#include <cstring>

using grpc::Channel;
using grpc::ClientContext;
using grpc::ClientReader;
using grpc::Status;

//New requestor
Requestor* RequestorInit(char* address){
    if( !address ) return NULL;
    req = malloc(1 * sizeof(Requestor));
    req->address = malloc((strlen(address)+1) * sizeof(char)) address;
    strcpy(req->address,address);
    return req;
}

void RequestorFree(Requestor* requestor){
    if(requestor){
        if(requestor->address){
            free(requestor->address);
            requestor->address = NULL;
        }
        free(requestor);
    }
}


// Fetch first entitled SVID.
x509svid_SVID* FetchDefaultX509SVID(Requestor* requestor){

    //gRPC channel and workload API stub
    std::shared_ptr<Channel> chan = grpc::CreateChannel(requestor->address,grpc::InsecureChannelCredentials());
    std::unique_ptr<SpiffeWorkloadAPI::Stub> stub = SpiffeWorkloadAPI::NewStub(chan);

    ClientContext ctx;
    ctx.AddMetadata("workload.spiffe.io","true"); //mandatory

    X509SVIDRequest req = X509SVIDRequest(); //empty request
    X509SVIDResponse response;
    
    auto c_reader = stub->FetchX509SVID(&ctx,req); //get response reader
    
    while (c_reader->Read(&response)){ //while there are messages
        x509svid_SVID* x509svid = NULL;
        auto ids = response.svids(); // all SVID's the workload is entitled to.
        for (auto &&id : ids)
        {  
            err_t err;
            //assemble SVID from response.
            x509svid = x509svid_Parse((byte*) id.x509_svid().data(),(byte*) id.x509_svid_key().data(),&err);
            if(err){
                return NULL;
            }else{
                return x509svid; //first SVID found.
            }
        }
        return x509svid; //no SVID in response
    }
    return NULL; //no response -> no SVID
}

// Fetch ALL entitled SVIDs. Array will need to be freed.
int FetchAllX509SVID(Requestor* requestor,x509svid_SVID** svids_pointer){

    //gRPC channel and workload API stub
    std::shared_ptr<Channel> chan = grpc::CreateChannel(requestor->address,grpc::InsecureChannelCredentials());
    std::unique_ptr<SpiffeWorkloadAPI::Stub> stub = SpiffeWorkloadAPI::NewStub(chan);

    ClientContext ctx;
    ctx.AddMetadata("workload.spiffe.io","true"); //mandatory

    X509SVIDRequest req = X509SVIDRequest(); //empty request
    X509SVIDResponse response;
    
    auto c_reader = stub->FetchX509SVID(&ctx,req); //get response reader
    *svids_pointer = NULL;
    while (c_reader->Read(&response)){ //while there are messages
        
        x509svid_SVID* x509svid = NULL;
        int svid_count = response.svids_size();
        //needs to be free'd
        *svids_pointer = malloc(sizeof(x509svid_SVID*) * svid_count);
        auto ids = response.svids(); // all SVID's the workload is entitled to.
        for (int i = 0; i < svid_count ; i++)
        {  
            err_t err;
            //assemble SVID from response.
            x509svid = x509svid_Parse((byte*) id.x509_svid().data(),(byte*) id.x509_svid_key().data(),&err);
            (*svids_pointer)[i] = x509svid;
        }
        return svid_count;
    }
    return 0; //no response -> no SVID
}
