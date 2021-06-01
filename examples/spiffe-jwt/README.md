# HTTP over TLS with JWT

This example shows how two services using HTTP can communicate using TLS with the server presenting an X509 SVID and expecting a client to authenticate with a JWT-SVID. The SVIDs are retrieved, and authentication is accomplished, via the SPIFFE Workload API.

The **HTTP server** creates a [workloadapi_X509Source](https://github.com/)