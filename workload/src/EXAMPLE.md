## Fetch SVID

Fetch SVID for C and C++ example.

### Requestor object
```
workloadapi_Requestor *requestor =
    workloadapi_RequestorInit("unix:///tmp/agent.sock");
```
Initialize request with address.

### SVID
```
x509svid_SVID *svid = workloadapi_FetchDefaultX509SVID(requestor);
```
Fetch SVID with requestor object.
```
svid->td;         // trust domain object
svid->certs;      // stb array of X509* certificate objects
svid->privateKey; // private key EVP_PKEY object
```

### Free
```
workloadapi_RequestorFree(requestor);
x509svid_SVID_Free(svid, true);
```
Don't forget to free allocated objects.

### Compiling
Compile with instructions in README.md

Run examples: 
```
./c_client
./cpp_client
```