#include "requestor.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
  workloadapi_Requestor *requestor =
      workloadapi_RequestorInit("unix:///tmp/agent.sock");

  x509bundle_Set *set = workloadapi_FetchX509Bundles(requestor);
  printf("Address : %p\n", set);

  if (set) {
    printf("Bundles map Address: %p\n", set->bundles);
    printf("Number of Bundles: %lu\n", shlenu(set->bundles));
  }
  workloadapi_RequestorFree(requestor);
  x509bundle_Set_Free(set);

  return 0;
}
