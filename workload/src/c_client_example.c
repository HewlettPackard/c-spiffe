#include "client.h"
#include <stdio.h>
#include <stdlib.h>

enum { X509_SVID, JWT_SVID };
#define SVID_TYPE X509_SVID

int main(void)
{
    err_t error = NO_ERROR;
    workloadapi_Client *client = workloadapi_NewClient(&error);
    if(error != NO_ERROR) {
        printf("client error! %d\n", (int) error);
    }
    workloadapi_Client_defaultOptions(client, NULL);
    error = workloadapi_Client_Connect(client);
    if(error != NO_ERROR) {
        printf("conn error! %d\n", (int) error);
    }

    if(SVID_TYPE == X509_SVID) {
        x509svid_SVID *svid = workloadapi_Client_FetchX509SVID(client, &error);
        if(error != NO_ERROR) {
            printf("fetch error! %d\n", (int) error);
        }
        printf("Address : %p\n", svid);

        if(svid) {
            printf("SVID Path: %s\n", svid->id.path);
            printf("Trust Domain: %s\n", svid->id.td.name);
            printf("Cert(s) Address: %p\n", svid->certs);
            printf("Key Address: %p\n", svid->private_key);
        }
        x509svid_SVID_Free(svid);
    } else if(SVID_TYPE == JWT_SVID) {
        jwtsvid_Params params = { .audience = NULL,
                                  .extra_audiences = NULL,
                                  .subject = { .td = NULL, .path = NULL } };
        jwtsvid_SVID *svid
            = workloadapi_Client_FetchJWTSVID(client, NULL, &error);
        if(error != NO_ERROR) {
            printf("fetch error! %d\n", (int) error);
        }
        printf("Address : %p\n", svid);

        if(svid) {
            printf("SVID Path: %s\n", svid->id.path);
            printf("Trust Domain: %s\n", svid->id.td.name);
            printf("Token: %s\n", svid->token);
            printf("Claims:\n");
            for(size_t i = 0, size = shlenu(svid->claims); i < size; ++i) {
                char *value
                    = json_dumps(svid->claims[i].value, JSON_DECODE_ANY);
                printf("key: %s, value: %s\n", svid->claims[i].key, value);
                free(value);
            }
        }
        jwtsvid_SVID_Free(svid);
    }

    error = workloadapi_Client_Close(client);
    if(error != NO_ERROR) {
        printf("close error! %d\n", (int) error);
    }
    workloadapi_Client_Free(client);
    if(error != NO_ERROR) {
        printf("client free error! %d\n", (int) error);
    }

    return 0;
}
