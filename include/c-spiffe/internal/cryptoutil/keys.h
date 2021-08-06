#ifndef INCLUDE_INTERNAL_CRYPTOUTIL_KEYS_H
#define INCLUDE_INTERNAL_CRYPTOUTIL_KEYS_H

#include <openssl/evp.h>
#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif

/**
 * Compares two public keys objects.
 *
 * \param pkey1 [in] First public key object pointer.
 * \param pkey2 [in] Second public key object pointer.
 * \returns <tt>true</tt> if both public key are equal, <tt>false</tt>
 * otherwise.
 */
bool cryptoutil_PublicKeyEqual(EVP_PKEY *pkey1, EVP_PKEY *pkey2);

/**
 * Compares two RSA public keys objects.
 *
 * \param pkey1 [in] First RSA public key object pointer.
 * \param pkey2 [in] Second RSA public key object pointer.
 * \returns <tt>true</tt> if both public key are equal, <tt>false</tt>
 * otherwise.
 */
bool cryptoutil_RSAPublicKeyEqual(RSA *key1, RSA *key2);

/**
 * Compares two EC public keys objects.
 *
 * \param pkey1 [in] First EC public key object pointer.
 * \param pkey2 [in] Second EC public key object pointer.
 * \returns <tt>true</tt> if both public key are equal, <tt>false</tt>
 * otherwise.
 */
bool cryptoutil_ECDSAPublicKeyEqual(const EC_KEY *key1, const EC_KEY *key2);
#ifdef __cplusplus
}
#endif

#endif