<!--
(C) Copyright 2020-2021 Hewlett Packard Enterprise Development LP

 

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

 

    http://www.apache.org/licenses/LICENSE-2.0

 

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.

-->

# X.509 SVID Watcher example

This example shows how a service can obtain automatically rotated X.509 SVIDs and JWT Bundles from the SPIFFE Workload API.

The first step is to create a Workload API client. The code assumes it is talking to [SPIRE](https://github.com/spiffe/spire).

```C++
    err_t err;
    workloadapi_Client *client = workloadapi_NewClient(&err);
    if(err) {
        // ...
    }
    workloadapi_Client_defaultOptions(client, NULL);
    err = workloadapi_Client_Connect(client);
    if(err) {
        // ...
    }
```

The library uses a X.509 context watcher [workloadapi_Watcher] to send updates (or errors) to clients.

```C++
    err = workloadapi_Client_WatchX509Context(client, watcher);
    if(err) {
        // ...
    }
```
The watcher will be notified every time an SVID is updated or an error occurs.

It is possible to watch for JWT Bundles updates:
```C++
    err = workloadapi_Client_WatchJWTBundles(client, watcher);
    if(err) {
        printf("Failed watching JWT bundles: %u\n", err);
    }
```

The watcher will be notified every time a JWT Bundle is updated or an error occurs. 

## Building
Build the spiffe-watcher example:

```bash
cd build/examples/
make
```

## Running
This example assumes the following preconditions:
- There is a SPIRE server and agent up and running.
- There is a Unix workload attestor configured.
- The trust domain is `example.org`
- The agent SPIFFE ID is `spiffe://example.org/host`.
- There is a `spiffe-watcher` user in the system.

### 1. Create the registration entry
Create the registration entry for the spiffe-watcher workload:
```bash
./spire-server entry create -spiffeID spiffe://example.org/spiffe-watcher \
                            -parentID spiffe://example.org/host \
                            -selector unix:user:root
```

### 2. Start the workload
Start the spiffe-watcher with the `spiffe-watcher` user:
```bash
./spiffe-watcher
```

The watcher prints the SVID SPIFFE ID every time an SVID is updated.
 
```
SVID updated for "spiffe://example.org/spiffe-watcher":
-----BEGIN CERTIFICATE-----
MIIB5TCCAYugAwIBAgIRAIkzRMvOixmAvYiJwow5AOUwCgYIKoZIzj0EAwIwHjEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBlNQSUZGRTAeFw0yMDA0MjIxNjA2MjJaFw0y
MDA0MjIxNzA2MzJaMB0xCzAJBgNVBAYTAlVTMQ4wDAYDVQQKEwVTUElSRTBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABISDihEjzQNw0lBVmG6N8g1dSxA5qZpd5Xyb
ilpilnmmZZsCXz3LkShtk3Jem7TfTDcpAVNWEApz4whSm78ICwOjgaowgacwDgYD
VR0PAQH/BAQDAgOoMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNV
HRMBAf8EAjAAMB0GA1UdDgQWBBSEyoGr5Y9bdpNedAwpxW9O6zBDmzAfBgNVHSME
GDAWgBTLGktJw00mGe07dUGY6JQkyghF3TAoBgNVHREEITAfhh1zcGlmZmU6Ly9l
eGFtcGxlLm9yZy93b3JrbG9hZDAKBggqhkjOPQQDAgNIADBFAiEAnOqqI+fKDPQn
QVgh01bmWy00DNWWYpKuAQakj9zk4PMCIDsNbYwEztgxlsb1DxZlqJpR2gZkdoAJ
FnFdqZr2XMrT
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIB4TCCAWegAwIBAgIRAP/k5B666y4MrrdwssWL6rUwCgYIKoZIzj0EAwMwHjEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBlNQSUZGRTAeFw0yMDA0MjIxNDM3NTBaFw0y
MDA0MjMxNDM4MDBaMB4xCzAJBgNVBAYTAlVTMQ8wDQYDVQQKEwZTUElGRkUwWTAT
BgcqhkjOPQIBBggqhkjOPQMBBwNCAARleC9KdQcH05tTgYfihasPGxeeo1kXztL4
1Th5vUF2D0In7kCcwZu3o9m9mguiJ4aeTFXL5QVU0ju6GiCdFXH/o4GFMIGCMA4G
A1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTLGktJw00m
Ge07dUGY6JQkyghF3TAfBgNVHSMEGDAWgBSHpfNXovA1rMD4ZMRU527TujnI6DAf
BgNVHREEGDAWhhRzcGlmZmU6Ly9leGFtcGxlLm9yZzAKBggqhkjOPQQDAwNoADBl
AjArmjEf1aHXvqfy9pOC+7ZKon22x1FV4tHbNWuRvPZEyy86cDCkU6uaBgjJ3GKR
+gcCMQDMoTlCekCTdCfHeQOy7kbr5fjXFiw0+SnO/4iFGBLnrDcnIIpxCdzKL4HW
gLI5JLc=
-----END CERTIFICATE-----

jwt bundle updated "example.org": {"keys":[{"kty":"EC","kid":"KULvTqUAs9SwuYGoO06ifavOQkA5Dkic","crv":"P-256","x":"WtHZ13-FO_B4SXhYbtXE-e7TmFl_txMOtY-Ls3jWPeE","y":"UNkGvC4MYOUXbgoHRCXGAtSTVE9zqXCkecjTB2cj9RA"}]}
jwt bundle updated "example.org": {"keys":[{"kty":"EC","kid":"KULvTqUAs9SwuYGoO06ifavOQkA5Dkic","
```
