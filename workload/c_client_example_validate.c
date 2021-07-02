#include "c-spiffe/workload/client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if(argc < 3) {
        printf("Too few arguments!\nUsage:\n\t./c_client_example_validade "
               "<filepath> <audience>\n");
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

    FILE *f = fopen(argv[1], "r");

    if(f) {
        string_t token = FILE_to_string(f);
        string_t audience = string_new(argv[2]);
        jwtsvid_SVID *svid = workloadapi_Client_ValidateJWTSVID(
            client, token, audience, &error);
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
        arrfree(token);
        arrfree(audience);
    } else {
        printf("Invalid file path!\n");
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
