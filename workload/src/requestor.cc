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
//for testing, RequestorInitWithStub should used directly
Requestor* RequestorInit(char* address){
    return RequestorInitWithStub(address,NULL);
}

Requestor* RequestorInitWithStub(char* address, stub_ptr stub){
    if( !address ) return NULL;
    Requestor* req = (Requestor*) malloc(1 * sizeof(Requestor));
    req->address = (char*) malloc((strlen(address)+1) * sizeof(char));
    strcpy(req->address,address);
    
    if (!stub){
        std::shared_ptr<Channel> chan = grpc::CreateChannel(req->address,grpc::InsecureChannelCredentials());
        std::unique_ptr<SpiffeWorkloadAPI::StubInterface> new_stub = SpiffeWorkloadAPI::NewStub(chan);
        req->stub = new_stub.release();
    }else{
        req->stub = stub;
    } //TODO should we free the stub later?
    
    return req;
}

void RequestorFree(Requestor* requestor){
    if(requestor){
        if(requestor->address){
            free(requestor->address);
            requestor->address = NULL;
        }
        // TODO Should we free the stub?
        // if(requestor->stub)
        // {
        //     free(requestor->stub;
        // }
        free(requestor);
    }
}


// Fetch first entitled SVID.
x509svid_SVID* FetchDefaultX509SVID(Requestor* requestor){

    ClientContext ctx;
    ctx.AddMetadata("workload.spiffe.io","true"); //mandatory

    X509SVIDRequest req = X509SVIDRequest(); //empty request
    X509SVIDResponse response;
    
    std::unique_ptr<grpc::ClientReaderInterface<X509SVIDResponse>> c_reader = ((SpiffeWorkloadAPI::Stub*)requestor->stub)->FetchX509SVID(&ctx,req); //get response reader
    
    while (c_reader->Read(&response)){ //while there are messages
        x509svid_SVID* x509svid = NULL;
        auto ids = response.svids(); // all SVID's the workload is entitled to.
        for (auto &&id : ids)
        {  
            err_t err;
            //assemble SVID from response.
            x509svid = x509svid_ParseRaw((byte*)id.x509_svid().data(),id.x509_svid().length(),(byte*) id.x509_svid_key().data(), id.x509_svid_key().length(),&err);
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
int FetchAllX509SVID(Requestor* requestor,x509svid_SVID*** svids_pointer){

    ClientContext ctx;
    ctx.AddMetadata("workload.spiffe.io","true"); //mandatory

    X509SVIDRequest req = X509SVIDRequest(); //empty request
    X509SVIDResponse response;
    
    std::unique_ptr<grpc::ClientReader<X509SVIDResponse>> c_reader = ((SpiffeWorkloadAPI::Stub*)requestor->stub)->FetchX509SVID(&ctx,req); //get response reader
    
    *svids_pointer = NULL;
    while (c_reader->Read(&response)){ //while there are messages
        
        x509svid_SVID* x509svid = NULL;
        int svid_count = response.svids_size();
        //needs to be free'd
        *svids_pointer = (x509svid_SVID**) malloc(sizeof(x509svid_SVID*) * svid_count);
        auto ids = response.svids(); // all SVID's the workload is entitled to.
        for (int i = 0; i < svid_count ; i++)
        {  
            err_t err;
            //assemble SVID from response.
            x509svid = x509svid_Parse((byte*) ids[i].x509_svid().data(),(byte*) ids[i].x509_svid_key().data(),&err);
            (*svids_pointer)[i] = x509svid;
        }
        return svid_count;
    }
    return 0; //no response -> no SVID
}
