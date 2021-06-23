#include "c-spiffe/svid/x509svid/svid.h"
#include "c-spiffe/svid/x509svid/verify.h"
#include "c-spiffe/internal/x509util/util.h"
#include <openssl/pem.h>

bool x509svid_Verify_cb(X509_STORE_CTX *store_ctx, x509bundle_Source *source,
                        spiffeid_ID *id)
{
    memset(id, 0, sizeof *id);

    if(store_ctx && source) {
        // get spiffe id from leaf
        X509 *leaf_cert = X509_STORE_CTX_get0_cert(store_ctx);
        err_t err;
        spiffeid_ID leaf_id = x509svid_IDFromCert(leaf_cert, &err);
        memcpy(id, &leaf_id, sizeof *id);

        if(!err) {
            // get bundle from trust domain and then get authorities
            err_t err;
            x509bundle_Bundle *bundle
                = x509bundle_Source_GetX509BundleForTrustDomain(
                    source, spiffeid_ID_TrustDomain(leaf_id), &err);

            if(!err && bundle) {
                // get root certificates and add them to local store
                X509 **roots = x509bundle_Bundle_X509Authorities(bundle);
                X509_STORE *store = X509_STORE_CTX_get0_store(store_ctx);
                for(size_t i = 0, size = arrlenu(roots); i < size; ++i) {
                    X509_STORE_add_cert(store, roots[i]);
                }

                // verify if there is a valid certificate chain in store_ctx
                const int ret = X509_verify_cert(store_ctx);

                return ret == 1;
            }
        }
    }

    return false;
}
