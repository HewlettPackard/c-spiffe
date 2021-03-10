## Fetch SVID

Fetch SVID and Bundles for for C and C++ example.
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
### Bundles X.509
``` C++
x509bundle_Set *set
    = workloadapi_Client_FetchX509Bundles(client, &error);
```
### Bundles JWT
``` C++
jwtbundle_Set *set
    = workloadapi_Client_FetchJWTBundles(client, &error);
```
### Free
Don't forget to free allocated objects.
``` C++
error = workloadapi_Client_Close(client);
error = workloadapi_Client_Free(client);
```
For SVIDs:
``` C++
x509svid_SVID_Free(svid);
```
``` C++
jwtsvid_SVID_Free(svid);
```
For bundles:
``` C++
x509bundle_Set_Free(set);
```
``` C++
jwtbundle_Set_Free(set);
```
### Compiling
Always compile with make.

Run examples: 
``` bash
./c_client svid_type=x509
./c_client svid_type=jwt
./cpp_client svid_type=x509
./cpp_client svid_type=jwt
./c_client_bundle bundle_type=x509
./c_client_bundle bundle_type=jwt
```