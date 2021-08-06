#ifndef INCLUDE_INTERNAL_JWTUTIL_UTIL_H
#define INCLUDE_INTERNAL_JWTUTIL_UTIL_H

#include "c-spiffe/utils/util.h"
#include <jansson.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    map_string_EVP_PKEY *jwt_auths;
    X509 **x509_auths;
    json_t *root;
} jwtutil_JWKS;

/**
 * Copy a stb string hash map of jwt authorities.
 *
 * \param hash [in] stb string hash map of public keys.
 * \returns A copy of hash. Must be freed iterating over hash using
 * EVP_PKEY_free and then shfree on the map.
 */
map_string_EVP_PKEY *jwtutil_CopyJWTAuthorities(map_string_EVP_PKEY *hash);

/**
 * Compares two stb string hash maps of jwt authorities.
 *
 * \param hash1 [in] First stb string hash map of public keys.
 * \param hash2 [in] Second stb string hash map of public keys.
 * \returns <tt>true</tt> if the maps have the same values for the same
 * keys, <tt>false</tt> otherwise.
 */
bool jwtutil_JWTAuthoritiesEqual(map_string_EVP_PKEY *hash1,
                                 map_string_EVP_PKEY *hash2);

/**
 * Parses a JWKS in raw bytes format
 *
 * \param bytes [in] ...
 * \param err [out] ...
 * \returns ...
 */
jwtutil_JWKS jwtutil_ParseJWKS(const char *bytes, err_t *err);

string_t jwtutil_JWKS_Marshal(jwtutil_JWKS *jwks, err_t *err);

void jwtutil_JWKS_Free(jwtutil_JWKS *jwks);

#ifdef __cplusplus
}
#endif

#endif
