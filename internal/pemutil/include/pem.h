#ifndef __INCLUDE_INTERNAL_PEMUTIL_PEM_H__
#define __INCLUDE_INTERNAL_PEMUTIL_PEM_H__

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "../../../utils/include/util.h"

// X509 *d2i_X509(X509 **px, const byte **in, long len);
// PEM_read_bio_X509(BIO *bioptr, NULL, NULL, NULL);
// PEM_read_bio_PKCS8_PRIV_KEY_INFO(BIO *bioptr, NULL, NULL, NULL);
// int PEM_read_bio(BIO *bp, char **name, char **header,
                //   unsigned char **data, long *len);

X509** pemutil_ParseCertificate(const byte *bytes, err_t *err);
EVP_PKEY* pemutil_ParsePrivateKey(const byte *bytes, err_t *err);
byte* pemutil_EncodePKCS8PrivateKey(const EVP_PKEY *pkey, err_t *err);
byte* pemutil_EncodeCertificates(const X509 **certs);

/*
func parseBlocks(blocksBytes []byte, expectedType string) ([]interface{}, error)
func parseBlock(pemBytes []byte, pemType string) (interface{}, []byte, error)
*/

#endif