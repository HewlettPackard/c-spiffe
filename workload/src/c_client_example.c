#include "requestor.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char const *argv[])
{
    Requestor* requestor = RequestorInit("unix:///tmp/agent.sock");
    
    x509svid_SVID* svid = FetchDefaultX509SVID(requestor);
    printf("Address : %p\n",svid);

    if(svid){
            printf("SVID Path: %s\n",svid->id.path);
            printf("Trust Domain: %s\n",svid->id.td.name);
            printf("Cert(s) Address: %p\n",svid->certs);
            printf("Key Address: %p\n",svid->privateKey);
        free(svid);
    }
    RequestorFree(requestor);
    x509svid_SVID_Free(svid,true);
    return 0;
}
