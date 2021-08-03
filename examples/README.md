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


# C-spiffe Examples

This section contains a set of standalone examples that demonstrate different use cases for the C-spiffe library.

## Use cases

- [Mutually Authenticated TLS (mTLS)](spiffe-tls/README.md): _Establish mTLS connections between workloads using automatically rotated X.509 SVIDs obtained from the SPIFFE Workload API._

- [HTTP over TLS with JWT and X.509 SVIDs](spiffe-jwt/README.md): _Send HTTP requests between workloads over a TLS + JWT authentication using automatically rotated X.509 SVIDs and JWT SVIDs from the SPIFFE Workload API._

- [HTTP over mTLS](spiffe-http/README.md): _Send HTTP requests between workloads over mTLS using automatically rotated X.509 SVIDs obtained from the SPIFFE Workload API._ 
