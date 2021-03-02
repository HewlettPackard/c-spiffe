## Fetch SVID

Fetch SVID for C and C++ example. First define which type of svid you want.
``` C++
#define BUNDLE_TYPE X509_BUNDLE
/* OR */
#define BUNDLE_TYPE JWT_BUNDLE
```
### Client object
``` C++
err_t error;
workloadapi_Client *Client = workloadapi_NewClient(&error);
workloadapi_Client_SetAddress(client, "unix:///tmp/agent.sock");
workloadapi_Client_SetHeader(client, "workload.spiffe.io","true");
error = workloadapi_Client_Connect(client);
```
Initialize client with address.

### SVID X.509
``` C++
x509svid_SVID *svid = workloadapi_FetchX509SVID(Client);
```
Fetch SVID with Client object.
``` C++
svid->id;            // spiffe ID
svid->id.td;         // trust domain object
svid->certs;         // stb array of X509* certificate objects
svid->private_key;   // private key EVP_PKEY object
```

### SVID JWT
``` C++
jwtsvid_SVID *svid = workloadapi_FetchJWTSVID(Client);
```
Fetch SVID with Client object.
``` C++
svid->id;            // spiffe ID
svid->id.td;         // trust domain object
svid->token;         // raw jwt token
svid->claims;        // map for key to json object of claims
```
### Free
``` C++
error = workloadapi_Client_Close(client);
error = workloadapi_Client_Free(client);
x509svid_SVID_Free(svid, true);
```
OR
``` C++
error = workloadapi_Client_Close(client);
error = workloadapi_Client_Free(client);
jwtsvid_SVID_Free(svid, true);
```
Don't forget to free allocated objects.

### Compiling
Compile with instructions in README.md

Run examples: 
``` bash
./c_client
./cpp_client
```