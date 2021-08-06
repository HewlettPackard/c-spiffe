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
