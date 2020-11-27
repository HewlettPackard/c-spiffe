#ifndef __INCLUDE_INTERNAL_CRYPTOUTIL_KEYS_H__
#define __INCLUDE_INTERNAL_CRYPTOUTIL_KEYS_H__

#include <stdbool.h>
#include <openssl/evp.h>

bool cryptoutil_PublicKeyEqual(const EVP_PKEY *pkey1, const EVP_PKEY *pkey2);
bool cryptoutil_RSAPublicKeyEqual(const RSA *key1, const RSA *key2);
bool cryptoutil_ECDSAPublicKeyEqual(const EC_KEY *key1, const EC_KEY *key2);

#endif