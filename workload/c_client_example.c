#include "c-spiffe/workload/client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if(argc < 2) {
        printf("Too few arguments!\nUsage:\n\t./c_client "
               "svid_type=jwt\n\t./c_client svid_type=x509\n");
        exit(-1);
    }

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

    if(strcmp(argv[1], "svid_type=x509") == 0) {
        x509svid_SVID *svid = workloadapi_Client_FetchX509SVID(client, &error);
        if(error != NO_ERROR) {
            printf("fetch error! %d\n", (int) error);
        }
        printf("Address: %p\n", svid);

        if(svid) {
            printf("SVID Path: %s\n", svid->id.path);
            printf("Trust Domain: %s\n", svid->id.td.name);
            printf("Cert(s) Address: %p\n", svid->certs);
            printf("Key Address: %p\n", svid->private_key);

            x509svid_SVID_Free(svid);
        }
    } else if(strcmp(argv[1], "svid_type=jwt") == 0) {
        // spiffeid_ID id = { .td = string_new("example.org"),
        //                    .path = string_new("/workload1") };
        spiffeid_ID id = { NULL, NULL };
        string_t audience = string_new("spiffe://example.org/audience1");
        jwtsvid_Params params
            = { .audience = audience, .extra_audiences = NULL, .subject = id };
        jwtsvid_SVID *svid
            = workloadapi_Client_FetchJWTSVID(client, &params, &error);
        if(error != NO_ERROR) {
            printf("fetch error! %d\n", (int) error);
        }
        printf("Address: %p\n", svid);

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
            jwtsvid_SVID_Free(svid);
        }
        spiffeid_ID_Free(&id);
        arrfree(audience);
    } else {
        printf("Invalid argument!\n");

        printf("Usage:\n\t./c_client "
               "svid_type=jwt\n\t./c_client svid_type=x509\n");
        exit(-1);
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
