#include "client.h"
#include <cstdio>
#include <cstdlib>
#include <iostream>

int main(void)
{
  err_t error = NO_ERROR;
  workloadapi_Client *client = workloadapi_NewClient(&error);
  if (error != NO_ERROR)
  {
    std::cout << "client error! " << (int)error <<std::endl;
  }
  workloadapi_defaultClientOptions(client, NULL);
  error = workloadapi_ConnectClient(client);
  if (error != NO_ERROR)
  {
    std::cout << "conn error! " << (int)error <<std::endl;
  }
  x509svid_SVID *svid = workloadapi_FetchX509SVID(client, &error);
  if (error != NO_ERROR)
  {
    std::cout << "fetch error! " << (int)error <<std::endl;
  }
  std::cout << "Address:" << svid << std::endl;
  if (svid)
  {
    std::cout << "SVID Path: " << svid->id.path << std::endl
              << "Trust Domain: " << svid->id.td.name << std::endl
              << "Cert(s) Address: " << svid->certs << std::endl
              << "Key Address: " << svid->privateKey << std::endl;
  }
  workloadapi_FreeClient(client);
  x509svid_SVID_Free(svid, true);
  return 0;
}
