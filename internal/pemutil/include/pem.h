#ifndef __INCLUDE_INTERNAL_PEMUTIL_PEM_H__
#define __INCLUDE_INTERNAL_PEMUTIL_PEM_H__

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "../../../utils/include/util.h"

typedef struct pemutil_Block
{
    string_t type;
    // map_string_string *headers;
    byte *bytes;
} pemutil_Block;

X509** pemutil_ParseCertificates(const byte *bytes, err_t *err);
EVP_PKEY* pemutil_ParsePrivateKey(
                                const byte *bytes, 
                                err_t *err);
byte* pemutil_EncodePrivateKey(
                                EVP_PKEY *pkey, 
                                int *bytes_len, 
                                err_t *err);
byte** pemutil_EncodeCertificates(X509 **certs);

/*
func parseBlocks(blocksBytes []byte, expectedType string) ([]interface{}, error)
func parseBlock(pemBytes []byte, pemType string) (interface{}, []byte, error)
*/

#endif