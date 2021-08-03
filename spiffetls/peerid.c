
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

#include "c-spiffe/spiffetls/peerid.h"
#include "c-spiffe/svid/x509svid/svid.h"

spiffeid_ID spiffetls_PeerIDFromConn(SSL *conn, err_t *err)
{
    spiffeid_ID id = { .td = { NULL }, .path = NULL };

    if(conn) {
        X509 *cert = SSL_get_peer_certificate(conn);
        if(cert) {
            id = x509svid_IDFromCert(cert, err);

            if(*err) {
                // unable to get peer ID
                *err = ERR_GET;
            }
            X509_free(cert);
        } else {
            // no peer certificate
            *err = ERR_NO_PEER_CERTIFICATE;
        }
    } else {
        // connection is NULL
        *err = ERR_CONNECT;
    }

    return id;
}
