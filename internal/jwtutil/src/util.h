#ifndef __INCLUDE_INTERNAL_JWTUTIL_UTIL_H__
#define __INCLUDE_INTERNAL_JWTUTIL_UTIL_H__

#include <stdbool.h>
#include "../../../utils/src/util.h"

#ifdef __cplusplus
extern "C" {
#endif

map_string_EVP_PKEY* jwtutil_CopyJWTAuthorities(map_string_EVP_PKEY *hash);
bool jwtutil_JWTAuthoritiesEqual(
        map_string_EVP_PKEY *hash1, 
        map_string_EVP_PKEY *hash2);

#ifdef __cplusplus
}
#endif

#endif