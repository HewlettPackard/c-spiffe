#include "requestor.h"
#include <cstdio>
#include <cstdlib>
#include <iostream>

int main(int argc, char const *argv[])
{
    Requestor* requestor = RequestorInit("unix:///tmp/agent.sock");
    x509svid_SVID* svid = FetchDefaultX509SVID(requestor);
    std::cout << "Address:" << svid << std::endl;
    if(svid){
        std::cout <<"SVID Path: " << svid->id.path << std::endl << "Trust Domain: " << svid->id.td.name << std::endl << "Cert(s) Address: " << svid->certs << std::endl << "Key Address: " << svid->privateKey << std::endl;
    }
    RequestorFree(requestor);
    x509svid_SVID_Free(svid,true);
    return 0;
}
