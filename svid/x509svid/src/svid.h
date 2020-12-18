#ifndef __INCLUDE_SVID_X509SVID_SVID_H__
#define __INCLUDE_SVID_X509SVID_SVID_H__

#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include "../../../spiffeid/src/id.h"
#include "../../../internal/pemutil/src/pem.h"
#include "../../../internal/x509util/src/util.h"

typedef struct x509svid_SVID
{
    //its own spiffe id
    spiffeid_ID id;
    //stb array of X509 certificate pointers
    X509 **certs;
    //its own private key
    EVP_PKEY *privateKey;
} x509svid_SVID;

x509svid_SVID* x509svid_Load(const string_t certfile, 
                                const string_t keyfile, 
                                err_t *err);
x509svid_SVID* x509svid_Parse(const byte *certbytes, 
                                const byte *keybytes, 
                                err_t *err);
x509svid_SVID* x509svid_ParseRaw(const byte *certbytes, 
                                    const byte *keybytes, 
                                    err_t *err);
x509svid_SVID* x509svid_newSVID(X509 **certs, 
                                EVP_PKEY *pkey, 
                                err_t *err);

spiffeid_ID x509svid_validateCertificates(X509 **certs, err_t *err);
spiffeid_ID x509svid_validateLeafCertificate(X509 *cert, err_t *err);
void x509svid_validateSigningCertificates(X509 **certs, err_t *err);
void x509svid_validateKeyUsage(X509 *cert, err_t *err);

void x509svid_SVID_Marshal(const x509svid_SVID *svid, 
                            byte **rawbytes1, 
                            byte **rawbytes2, 
                            err_t *err);
void x509svid_SVID_MarshalRaw(const x509svid_SVID *svid, 
                                byte **rawbytes1, 
                                byte **rawbytes2, 
                                err_t *err);
x509svid_SVID* x509svid_SVID_GetX509SVID(x509svid_SVID *svid, 
                                            err_t *err);

EVP_PKEY* x509svid_validatePrivateKey(EVP_PKEY *pkey, 
                                        X509 *cert, 
                                        err_t *err);
/*
func keyMatches(privateKey crypto.PrivateKey, publicKey crypto.PublicKey) (bool, error) {
*/

#endif