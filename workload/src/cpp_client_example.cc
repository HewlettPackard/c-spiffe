#include "client.h"
#include <cstdio>
#include <cstdlib>
#include <iostream>

enum { X509_SVID, JWT_SVID };
#define SVID_TYPE X509_SVID

int main(void)
{
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

    if(SVID_TYPE == X509_SVID) {
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
        }
        x509svid_SVID_Free(svid);
    } else if(SVID_TYPE == JWT_SVID) {
        jwtsvid_Params params{ NULL, NULL, { NULL, NULL } };
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
        }
        jwtsvid_SVID_Free(svid);
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
