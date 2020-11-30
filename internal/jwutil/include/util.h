#ifndef __INCLUDE_INTERNAL_JWUTIL_UTIL_H__
#define __INCLUDE_INTERNAL_JWUTIL_UTIL_H__

#include <stdbool.h>
#include "../../../utils/include/util.h"

map_string_EVP_PKEY* jwutil_CopyJWTAuthorities(const map_string_EVP_PKEY *hash);
bool jwutil_JWTAuthoritiesEqual(
        map_string_EVP_PKEY *hash1, 
        map_string_EVP_PKEY *hash2);

#endif