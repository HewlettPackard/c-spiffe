#include "internal/jwtutil/src/util.h"
#include "internal/cryptoutil/src/keys.h"
#include <cjose/cjose.h>
#include <jansson.h>
#include <openssl/x509.h>

typedef struct _ec_keydata_int {
    cjose_jwk_ec_curve crv;
    EC_KEY *key;
} ec_keydata;

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

jwtutil_JWKS jwtutil_ParseJWKS(const char *bytes, err_t *err)
{
    jwtutil_JWKS pair = { .jwt_auths = NULL, .x509_auths = NULL };
    *err = NO_ERROR;

    if(bytes) {
        json_error_t j_err;
        json_t *root = json_loads(bytes, 0, &j_err);
        if(!root) {
            // could not load json
            *err = ERROR2;
            goto error1;
        }

        json_t *keys = json_object_get(root, "keys");
        if(!keys) {
            // no key with name "keys"
            *err = ERROR3;
            goto error1;
        } else if(json_typeof(keys) != JSON_ARRAY) {
            // object is not an array
            *err = ERROR3;
            goto error1;
        }

        sh_new_strdup(pair.jwt_auths);
        const int n_keys = json_array_size(keys);
        bool err_flag = false;
        for(int i = 0; i < n_keys && !err_flag; ++i) {
            // get i-th element of the JWKS
            json_t *elem_obj = json_array_get(keys, i);
            if(!elem_obj) {
                err_flag = true;
                goto error2;
            }

            cjose_err cj_err;
            // import json object into a JWK object
            cjose_jwk_t *jwk = cjose_jwk_import_json(elem_obj, &cj_err);
            if(!jwk) {
                err_flag = true;
                goto error2;
            }

            json_t *use_json = json_object_get(elem_obj, "use");
            const char *use_str = NULL;
            if(use_json)
                use_str = json_typeof(use_json) == JSON_STRING
                              ? json_string_value(use_json)
                              : "none";

            if(!use_str || strcmp(use_str, "x509-svid") != 0) {
                // get key type
                const cjose_jwk_kty_t kty = cjose_jwk_get_kty(jwk, &cj_err);
                // get key data
                void *keydata = cjose_jwk_get_keydata(jwk, &cj_err);
                if(!keydata) {
                    err_flag = true;
                    goto error2;
                }
                EVP_PKEY *pkey = EVP_PKEY_new();
                switch(kty) {
                case CJOSE_JWK_KTY_RSA:
                    EVP_PKEY_set1_RSA(pkey, (RSA *) keydata);
                    break;
                case CJOSE_JWK_KTY_EC:
                    EVP_PKEY_set1_EC_KEY(pkey, ((ec_keydata *) keydata)->key);
                    break;
                default:
                    // type not supported currently
                    EVP_PKEY_free(pkey);
                    pkey = NULL;
                    err_flag = true;
                }

                // get key id field
                const char *kid = cjose_jwk_get_kid(jwk, &cj_err);
                if(!kid) {
                    err_flag = true;
                    goto error2;
                }
                if(pkey) {
                    // insert id and its public key on the map
                    shput(pair.jwt_auths, kid, pkey);
                }
            } else {
                json_t *certs_json = json_object_get(elem_obj, "x5c");
                if(!certs_json) {
                    err_flag = true;
                    goto error2;
                } else if(json_typeof(certs_json) != JSON_ARRAY) {
                    err_flag = true;
                    goto error2;
                } else if(json_array_size(certs_json) != 1) {
                    err_flag = true;
                    goto error2;
                }

                json_t *leaf_json = json_array_get(certs_json, 0);
                const char *leaf_str = NULL;
                if(leaf_json)
                    leaf_str = json_typeof(leaf_json) == JSON_STRING
                                   ? json_string_value(leaf_json)
                                   : NULL;

                uint8_t *buffer;
                size_t buffer_len;
                cjose_base64_decode(leaf_str, strlen(leaf_str), &buffer,
                                    &buffer_len, NULL);
                const uint8_t *buffer_out = buffer;
                X509 *cert = d2i_X509(NULL, &buffer_out, buffer_len);
                if(cert) {
                    arrput(pair.x509_auths, cert);
                }

                free(buffer);
            }
error2:
            cjose_jwk_release(jwk);
        }

        if(err_flag) {
            *err = ERROR4;
            jwtutil_JWKS_Free(&pair);
        }
error1:
        if(root) {
            free(root);
        }

        return pair;
    }

    // null pointer error
    *err = ERROR1;
    return pair;
}

void jwtutil_JWKS_Free(jwtutil_JWKS *jwks)
{
    if(jwks) {
        for(size_t i = 0, size = arrlenu(jwks->x509_auths); i < size; ++i) {
            X509_free(jwks->x509_auths[i]);
        }
        arrfree(jwks->x509_auths);
        for(size_t i = 0, size = shlenu(jwks->jwt_auths); i < size; ++i) {
            EVP_PKEY_free(jwks->jwt_auths[i].value);
        }
        shfree(jwks->jwt_auths);
    }
}
