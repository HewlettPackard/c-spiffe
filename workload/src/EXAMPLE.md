## Fetch SVID

Fetch SVID for C and C++ example.

### Client object
``` C++
err_t error;
workloadapi_Client *Client = workloadapi_NewClient(&error);
workloadapi_Client_SetAddress(client, "unix:///tmp/agent.sock");
workloadapi_Client_SetHeader(client, "workload.spiffe.io","true");
error = workloadapi_Client_Connect(client);
```
Initialize client with address.

### SVID
``` C++
x509svid_SVID *svid = workloadapi_FetchX509SVID(Client);
```
Fetch SVID with Client object.
``` C++
svid->td;         // trust domain object
svid->certs;      // stb array of X509* certificate objects
svid->privateKey; // private key EVP_PKEY object
```

### Free
``` C++
error = workloadapi_Client_Close(client);
error = workloadapi_Client_Free(client);
x509svid_SVID_Free(svid, true);
```
Don't forget to free allocated objects.

### Compiling
Compile with instructions in README.md

Run examples: 
``` bash
./c_client
./cpp_client
```