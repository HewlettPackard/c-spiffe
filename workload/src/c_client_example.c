#include "requestor.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
  workloadapi_Requestor *requestor =
      workloadapi_RequestorInit("unix:///tmp/agent.sock");

  x509svid_SVID *svid = workloadapi_FetchDefaultX509SVID(requestor);
  printf("Address : %p\n", svid);

  if (svid) {
    printf("SVID Path: %s\n", svid->id.path);
    printf("Trust Domain: %s\n", svid->id.td.name);
    printf("Cert(s) Address: %p\n", svid->certs);
    printf("Key Address: %p\n", svid->private_key);
  }
  workloadapi_RequestorFree(requestor);
  x509svid_SVID_Free(svid);

  return 0;
}
