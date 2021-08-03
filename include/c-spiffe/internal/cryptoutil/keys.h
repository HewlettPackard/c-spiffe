/**

(C) Copyright 2020-2021 Hewlett Packard Enterprise Development LP

 

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

 

    http://www.apache.org/licenses/LICENSE-2.0

 

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.

**/

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