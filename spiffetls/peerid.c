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
                *err = ERROR3;
            }
            X509_free(cert);
        } else {
            // no peer certificate
            *err = ERROR2;
        }
    } else {
        // connection is NULL
        *err = ERROR1;
    }

    return id;
}
