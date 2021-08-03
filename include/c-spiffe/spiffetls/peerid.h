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

#ifndef INCLUDE_SPIFFETLS_PEERID_H
#define INCLUDE_SPIFFETLS_PEERID_H

#include "c-spiffe/spiffeid/id.h"
#include "c-spiffe/utils/util.h"
#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Gets peer spiffe ID from given TLS connection, if it exists.
 *
 * \param conn [in] TLS connection object pointer.
 * \param err [out] Variable to get information in the event of error.
 * \returns spiffe ID object of the given connection, if it exists. Empty
 * spiffe ID, otherwise.
 */
spiffeid_ID spiffetls_PeerIDFromConn(SSL *conn, err_t *err);

#ifdef __cplusplus
}
#endif

#endif // INCLUDE_SPIFFETLS_PEERID_H
