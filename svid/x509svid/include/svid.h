#ifndef __INCLUDE_SVID_X509SVID_SVID_H__
#define __INCLUDE_SVID_X509SVID_SVID_H__

#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include "../../../spiffeid/include/id.h"
#include "../../../internal/pemutil/include/pem.h"
#include "../../../internal/x509util/include/util.h"

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
x509svid_SVID* x509svid_newSVID(const X509 **certs, 
                                const EVP_PKEY *pkey, 
                                err_t *err);

spiffeid_ID x509svid_validateCertificates(const X509 **certs, err_t *err);
spiffeid_ID x509svid_validateLeafCertificate(const X509 *cert, err_t *err);
void x509svid_validateSigningCertificates(const X509 **certs, err_t *err);
void x509svid_validateKeyUsage(const X509 *cert, err_t *err);

void x509svid_SVID_Marshal(const x509svid_SVID *svid, 
                            byte **rawbytes1, 
                            byte **rawbytes2, 
                            err_t *err);
void x509svid_SVID_MarshalRaw(const x509svid_SVID *svid, 
                                byte **rawbytes1, 
                                byte **rawbytes2, 
                                err_t *err);
x509svid_SVID* x509svid_SVID_GetX509SVID(const x509svid_SVID *svid, 
                                            err_t *err);

/*
func validatePrivateKey(privateKey crypto.PrivateKey, leaf *x509.Certificate) (crypto.Signer, error) {
func keyMatches(privateKey crypto.PrivateKey, publicKey crypto.PublicKey) (bool, error) {
*/

#endif