#include "internal/jwtutil/src/util.h"
#include "internal/cryptoutil/src/keys.h"

map_string_EVP_PKEY *jwtutil_CopyJWTAuthorities(map_string_EVP_PKEY *hash)
{
    if(hash) {
        map_string_EVP_PKEY *new_hash = NULL;
        sh_new_strdup(new_hash);

        for(size_t i = 0, size = shlenu(hash); i < size; ++i) {
            const char *str = hash[i].key;
            EVP_PKEY *pkey = hash[i].value;
            // ups the ref count, so it is memory safe
            // no need to copy the contents, for now
            EVP_PKEY_up_ref(pkey);

            shput(new_hash, str, pkey);
        }

        return new_hash;
    }
    return NULL;
}

bool jwtutil_JWTAuthoritiesEqual(map_string_EVP_PKEY *hash1,
                                 map_string_EVP_PKEY *hash2)
{
    if(hash1 && hash2) {
        const size_t sizeh1 = shlenu(hash1), sizeh2 = shlenu(hash2);

        if(sizeh1 != sizeh2)
            return false;

        // traverse hash1
        for(size_t i = 0; i < sizeh1; ++i) {
            // get key index, if it exists
            int j = shgeti(hash2, hash1[i].key);
            // if the key exists in hash2
            if(j >= 0) {
                // if pkeys are not equal
                if(!cryptoutil_PublicKeyEqual(hash1[i].value, hash2[j].value))
                    return false;
            } else
                return false;
        }

        return true;
    }

    return hash1 == hash2;
}
