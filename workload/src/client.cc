/*
 * Filename: /home/rlc2/Documents/c-spiffe/workload/src/client.c
 * Path: /home/rlc2/Documents/c-spiffe/workload/src
 * Created Date: Tuesday, December 22nd 2020, 1:22:45 pm
 * Author: Rodrigo Lopes (rlc2@cesar.org.br)
 * 
 * Copyright (c) 2020 CESAR
 */

// #include "proto/workload.pb.h"
// #include "proto/workload.grpc.pb.h"
#include "requestor.h"
#include <cstdio>
#include <cstdlib>
#include <iostream>

int main(int argc, char const *argv[])
{
    Requestor* requestor = RequestorInit("unix:///tmp/agent.sock");
    x509svid_SVID* svid = FetchDefaultX509SVID(requestor);
    if(svid){
        std::cout << "id:" << svid << std::endl << svid->id.path << std::endl << svid->id.td.name << std::endl << svid->certs << std::endl << svid->privateKey;
    }
    RequestorFree(requestor);
    return 0;
}
