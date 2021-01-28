#ifndef __INCLUDE_SVID_X509SVID_VERIFY_H__
#define __INCLUDE_SVID_X509SVID_VERIFY_H__

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "../../../spiffeid/src/id.h"
#include "../../../utils/src/util.h"
#include "../../../bundle/x509bundle/src/bundle.h"

#ifdef __cplusplus
extern "C" {
#endif

X509*** x509svid_ParseAndVerify(byte **raw_certs, 
                    x509bundle_Bundle *b, 
                    spiffeid_ID *id, 
                    err_t *err);
X509*** x509svid_Verify(X509 **certs, 
                    x509bundle_Bundle *b, 
                    spiffeid_ID *id, 
                    err_t *err);
spiffeid_ID x509svid_IDFromCert(X509 *cert, err_t *err);

//func Verify(certs []*x509.Certificate, bundleSource x509bundle.Source) (spiffeid.ID, [][]*x509.Certificate, error) {
#ifdef __cplusplus
}
#endif

#endif