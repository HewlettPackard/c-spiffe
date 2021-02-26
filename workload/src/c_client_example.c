#include "client.h"
#include <stdio.h>
#include <stdlib.h>

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
    error = workloadapi_Client_Close(client);
    if(error != NO_ERROR) {
        printf("close error! %d\n", (int) error);
    }
    workloadapi_Client_Free(client);
    if(error != NO_ERROR) {
        printf("client free error! %d\n", (int) error);
    }
    x509svid_SVID_Free(svid);

    return 0;
}
