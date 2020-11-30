#ifndef __INCLUDE_INTERNAL_CRYPTOUTIL_KEYS_H__
#define __INCLUDE_INTERNAL_CRYPTOUTIL_KEYS_H__

#include <stdbool.h>
#include <openssl/evp.h>

bool cryptoutil_PublicKeyEqual(EVP_PKEY *pkey1, EVP_PKEY *pkey2);
bool cryptoutil_RSAPublicKeyEqual(RSA *key1, RSA *key2);
bool cryptoutil_ECDSAPublicKeyEqual(const EC_KEY *key1, const EC_KEY *key2);

#endif