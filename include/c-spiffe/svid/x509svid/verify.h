/**

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

**/

#ifndef INCLUDE_SVID_X509SVID_VERIFY_H
#define INCLUDE_SVID_X509SVID_VERIFY_H

#include "c-spiffe/bundle/x509bundle/source.h"
#include "c-spiffe/spiffeid/id.h"
#include <openssl/x509.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Verifies a certificate store using the X.509 bundle source. It returns
 * the SPIFFE ID of the leaf certificate.
 *
 * \param store_ctx [in] X.509 certificate store.
 * \param source [in] Source of bundles.
 * \param id [out] SPIFFE ID of the leaf certificate.
 * \returns true if the verification is successful, false otherwise.
 */
bool x509svid_Verify_cb(X509_STORE_CTX *store_ctx, x509bundle_Source *source,
                        spiffeid_ID *id);

#ifdef __cplusplus
}
#endif

#endif
