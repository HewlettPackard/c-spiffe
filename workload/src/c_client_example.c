#include "client.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
  err_t error = NO_ERROR;
  workloadapi_Client *client = workloadapi_NewClient(&error);
  if(error != NO_ERROR) {
    printf("client error! %d\n",(int)error);
  }
  workloadapi_defaultClientOptions(client,NULL);
  error = workloadapi_ConnectClient(client);
  if(error != NO_ERROR) {
    printf("conn error! %d\n",(int)error);
  }
  x509svid_SVID *svid = workloadapi_FetchX509SVID(client,&error);
  if(error != NO_ERROR) {
    printf("fetch error! %d\n",(int)error);
  }
  printf("Address : %p\n", svid);

  if (svid) {
    printf("SVID Path: %s\n", svid->id.path);
    printf("Trust Domain: %s\n", svid->id.td.name);
    printf("Cert(s) Address: %p\n", svid->certs);
    printf("Key Address: %p\n", svid->privateKey);
  }
  workloadapi_FreeClient(client);
  x509svid_SVID_Free(svid, true);

  return 0;
}
