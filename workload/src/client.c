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
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char const *argv[])
{
    Requestor* requestor = RequestorInit("unix:///tmp/agent.sock");
    
    x509svid_SVID* svid = FetchDefaultX509SVID(requestor);
    printf("id: %p\n",svid);

    if(svid){
            printf("path: %s\n",svid->id.path);
            printf("td: %s\n",svid->id.td.name);
            printf("certs: %p\n",svid->certs);
            printf("key: %p\n",svid->privateKey);
        free(svid);
    }
    RequestorFree(requestor);

    return 0;
}
