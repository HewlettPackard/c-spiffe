#include "../include/util.h"
#include "../../cryptoutil/include/keys.h"

/**
 * TODO: does jwutil_CopyJWTAuthorities need to copy the
 * contents of the pointer or just the pointer?
 * 
 */

map_string_EVP_PKEY* jwutil_CopyJWTAuthorities(const map_string_EVP_PKEY *hash)
{
    if(hash)
    {
        map_string_EVP_PKEY *new_hash = NULL;

        for(size_t i = 0, size = shlenu(hash); i < size; ++i)
        {
            shput(new_hash, hash[i].key, hash[i].value);
        }

        return new_hash;
    }
    return NULL;
}

bool jwutil_JWTAuthoritiesEqual(
        map_string_EVP_PKEY *hash1, 
        map_string_EVP_PKEY *hash2)
{
    if(hash1 && hash2)
    {
        const size_t sizeh1 = shlenu(hash1), sizeh2 = shlenu(hash2);
        
        if(sizeh1 != sizeh2) return false;

        //traverse hash1
        for(size_t i = 0; i < sizeh1; ++i)
        {
            //get key index, if it exists
            int j = shgeti(hash2, hash1[i].key);
            //if the key exists in hash2
            if(j >= 0)
            {
                //if pkeys are not equal
                if(!cryptoutil_PublicKeyEqual(hash1[i].value, hash2[j].value))
                    return false;
            }
            else return false;
        }
    }
    return false;
}