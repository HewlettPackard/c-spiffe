#include "c-spiffe/workload/client.h"
#include <cstdio>
#include <cstdlib>
#include <iostream>

int main(int argc, char **argv)
{
    if(argc < 2) {
        std::cout << "Too few arguments!\nUsage:\n"
                  << "\t./cpp_client svid_type=jwt\n"
                  << "\t./cpp_client svid_type=x509\n";
        exit(-1);
    }
    std::string svid_type = argv[1];
    err_t error = NO_ERROR;

    workloadapi_Client *client = workloadapi_NewClient(&error);
    if(error != NO_ERROR) {
        std::cout << "client error! " << (int) error << std::endl;
    }
    workloadapi_Client_defaultOptions(client, NULL);
    error = workloadapi_Client_Connect(client);
    if(error != NO_ERROR) {
        std::cout << "conn error! " << (int) error << std::endl;
    }

    if(svid_type == "svid_type=x509") {
        x509svid_SVID *svid = workloadapi_Client_FetchX509SVID(client, &error);
        if(error != NO_ERROR) {
            std::cout << "fetch error! " << (int) error << std::endl;
        }
        std::cout << "Address:" << svid << std::endl;
        if(svid) {
            std::cout << "SVID Path: " << svid->id.path << std::endl
                      << "Trust Domain: " << svid->id.td.name << std::endl
                      << "Cert(s) Address: " << svid->certs << std::endl
                      << "Key Address: " << svid->private_key << std::endl;
            x509svid_SVID_Free(svid);
        }
    } else if(svid_type == "svid_type=jwt") {
        spiffeid_ID id{ string_new("example.com"), string_new("/workload1") };
        jwtsvid_Params params{ NULL, NULL, id };
        jwtsvid_SVID *svid
            = workloadapi_Client_FetchJWTSVID(client, &params, &error);
        if(error != NO_ERROR) {
            std::cout << "fetch error! " << (int) error << std::endl;
        }
        std::cout << "Address:" << svid << std::endl;
        if(svid) {
            std::cout << "SVID Path: " << svid->id.path << std::endl
                      << "Trust Domain: " << svid->id.td.name << std::endl
                      << "Token: " << svid->token << std::endl
                      << "Claims: " << std::endl;
            for(size_t i = 0, size = shlenu(svid->claims); i < size; ++i) {
                char *value
                    = json_dumps(svid->claims[i].value, JSON_DECODE_ANY);
                std::cout << "key: " << svid->claims[i].key << ", "
                          << "value: " << value << std::endl;
                free(value);
            }
            jwtsvid_SVID_Free(svid);
        }
        spiffeid_ID_Free(&id);
    } else {
        std::cout << "Invalid argument!" << std::endl;

        std::cout << "Usage:\n"
                  << "\t./cpp_client svid_type=jwt\n"
                  << "\t./cpp_client svid_type=x509\n";
        exit(-1);
    }

    error = workloadapi_Client_Close(client);
    if(error != NO_ERROR) {
        std::cout << "close error! " << (int) error << std::endl;
    }
    workloadapi_Client_Free(client);
    if(error != NO_ERROR) {
        std::cout << "free client error! " << (int) error << std::endl;
    }

    return 0;
}
