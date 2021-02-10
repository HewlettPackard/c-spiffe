#include "client.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
   err_t error = NO_ERROR;
  workloadapi_Client *client = workloadapi_NewClient(&error);
  x509svid_SVID *svid = workloadapi_FetchX509SVID(client,&error);
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
