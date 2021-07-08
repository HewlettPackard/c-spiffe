#include "c-spiffe/internal/jwtutil/util.h"
#include "c-spiffe/internal/cryptoutil/keys.h"
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
    jwtutil_JWKS jwks
        = { .jwt_auths = NULL, .x509_auths = NULL, .root = NULL };
    *err = NO_ERROR;

    if(bytes) {
        json_error_t j_err;
        json_t *root = json_loads(bytes, 0, &j_err);
        if(!root) {
            // could not load json
            *err = ERR_NULL;
            goto error1;
        }

        json_t *keys = json_object_get(root, "keys");
        if(!keys) {
            // no key with name "keys"
            *err = ERR_INVALID_DATA;
            goto error1;
        } else if(json_typeof(keys) != JSON_ARRAY) {
            // object is not an array
            *err = ERR_INVALID_DATA;
            goto error1;
        }
        jwks.root = root;

        sh_new_strdup(jwks.jwt_auths);
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
                    shput(jwks.jwt_auths, kid, pkey);
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
                if(leaf_json) {
                    leaf_str = json_typeof(leaf_json) == JSON_STRING
                                   ? json_string_value(leaf_json)
                                   : NULL;
                }
                uint8_t *buffer;
                size_t buffer_len;
                cjose_base64_decode(leaf_str, strlen(leaf_str), &buffer,
                                    &buffer_len, NULL);
                const uint8_t *buffer_out = buffer;
                X509 *cert = d2i_X509(NULL, &buffer_out, buffer_len);
                if(cert) {
                    arrput(jwks.x509_auths, cert);
                }

                free(buffer);
            }
error2:
            cjose_jwk_release(jwk);
        }

        if(err_flag) {
            *err = ERR_BAD_REQUEST;
            jwtutil_JWKS_Free(&jwks);
            root = NULL;
        }
error1:
        if(root && !jwks.root) {
            free(root);
        }

        return jwks;
    }

    // null pointer error
    *err = ERR_NULL;
    return jwks;
}

static char *BN_to_str(const BIGNUM *bn)
{
    int num_bytes;
    if(bn && (num_bytes = BN_num_bytes(bn)) > 0) {
        // set raw array of bytes
        byte *out_bn = NULL;
        arrsetlen(out_bn, num_bytes);
        BN_bn2bin(bn, out_bn);

        // raw array of bytes to base64
        char *out_bn_base64 = NULL;
        size_t out_bn_base64_len;
        cjose_err j_err;
        cjose_base64url_encode(out_bn, arrlenu(out_bn), &out_bn_base64,
                               &out_bn_base64_len, &j_err);
        out_bn_base64[out_bn_base64_len] = 0;
        arrfree(out_bn);

        return out_bn_base64;
    }

    return NULL;
}

static const char *NID_curve_to_str(int nid)
{
    switch(nid) {
    case NID_X9_62_prime192v1:
    case NID_X9_62_prime192v2:
    case NID_X9_62_prime192v3:
        return "P-192";
    case NID_X9_62_prime239v1:
    case NID_X9_62_prime239v2:
    case NID_X9_62_prime239v3:
        return "P-239";
    case NID_X9_62_prime256v1:
        return "P-256";
    case NID_secp384r1:
        return "P-384";
    case NID_secp521r1:
        return "P-521";
    default:
        return NULL;
    }
}

static json_t *EC_KEY_to_json(const EC_KEY *key)
{
    if(key) {
        const EC_GROUP *group = EC_KEY_get0_group(key);
        const EC_POINT *point = EC_KEY_get0_public_key(key);
        BIGNUM *X = BN_new(), *Y = BN_new();
        BN_CTX *ctx = BN_CTX_new();
        EC_POINT_get_affine_coordinates(group, point, X, Y, ctx);
        char *X_str = BN_to_str(X), *Y_str = BN_to_str(Y);
        BN_free(X);
        BN_free(Y);
        BN_CTX_free(ctx);

        const int crv_nid = EC_GROUP_get_curve_name(group);
        json_t *key_json
            = json_pack("{s:s,s:s*,s:s,s:s}", "kty", "EC", "crv",
                        NID_curve_to_str(crv_nid), "x", X_str, "y", Y_str);

        free(X_str);
        free(Y_str);

        return key_json;
    }

    return NULL;
}

static json_t *RSA_to_json(const RSA *key)
{
    if(key) {
        const BIGNUM *N = NULL, *E = NULL;
        RSA_get0_key(key, &N, &E, NULL);
        char *N_str = BN_to_str(N), *E_str = BN_to_str(E);

        json_t *key_json
            = json_pack("{s:s,s:s,s:s}", "kty", "RSA", "n", N_str, "e", E_str);

        free(N_str);
        free(E_str);

        return key_json;
    }

    return NULL;
}

static json_t *EVP_PKEY_to_json(EVP_PKEY *pubkey)
{
    if(pubkey) {
        const int type = EVP_PKEY_base_id(pubkey);
        switch(type) {
        case EVP_PKEY_EC:
            return EC_KEY_to_json(EVP_PKEY_get0_EC_KEY(pubkey));
        case EVP_PKEY_RSA:
            return RSA_to_json(EVP_PKEY_get0_RSA(pubkey));
        }
    }

    return NULL;
}

static json_t *X509_to_json(X509 *cert)
{
    if(cert) {
        unsigned char *out_cert = NULL;
        int out_cert_len = i2d_X509(cert, &out_cert);
        if(out_cert_len > 0) {
            char *out_cert_base64 = NULL;
            size_t out_cert_base64_len;
            cjose_err j_err;
            cjose_base64_encode(out_cert, out_cert_len, &out_cert_base64,
                                &out_cert_base64_len, &j_err);
            out_cert_base64[out_cert_base64_len] = 0;
            OPENSSL_free(out_cert);
            json_t *x5c_json = json_pack("[s]", out_cert_base64);
            free(out_cert_base64);

            return x5c_json;
        }
    }

    return NULL;
}

static json_t *x509svid_to_json(X509 *cert)
{
    if(cert) {
        json_t *key_json = json_pack("{s:s}", "use", "x509-svid");

        json_t *pubkey_json = EVP_PKEY_to_json(X509_get_pubkey(cert));
        if(pubkey_json) {
            json_object_update(key_json, pubkey_json);
            json_decref(pubkey_json);
            json_object_set_new(key_json, "x5c", X509_to_json(cert));
            
            return key_json;
        }
    }

    return NULL;
}

static json_t *jwtsvid_to_json(map_string_EVP_PKEY *pair)
{
    if(pair) {
        json_t *key_json
            = json_pack("{s:s,s:s}", "use", "jwt-svid", "kid", pair->key);

        json_t *pubkey_json = EVP_PKEY_to_json(pair->value);
        if(pubkey_json) {
            json_object_update(key_json, pubkey_json);
            json_decref(pubkey_json);
            
            return key_json;
        }
    }

    return NULL;
}

string_t jwtutil_JWKS_Marshal(jwtutil_JWKS *jwks, err_t *err)
{
    string_t jwks_str = NULL;
    if(jwks) {
        if(!jwks->root) {
            json_t *jwks_json = NULL;
            json_t *keys_json = json_array();

            for(size_t i = 0, size = arrlenu(jwks->x509_auths); i < size;
                ++i) {
                json_array_append_new(keys_json,
                                      x509svid_to_json(jwks->x509_auths[i]));
            }
            for(size_t i = 0, size = shlenu(jwks->jwt_auths); i < size; ++i) {
                json_array_append_new(keys_json,
                                      jwtsvid_to_json(jwks->jwt_auths + i));
            }

            jwks_json = json_object();
            json_object_set_new(jwks_json, "keys", keys_json);
            jwks->root = jwks_json;
        }
        // get size first
        const size_t len = json_dumpb(jwks->root, NULL, 0,
                                      JSON_PRESERVE_ORDER | JSON_ENSURE_ASCII);

        // allocate and set string
        arrsetlen(jwks_str, len);
        json_dumpb(jwks->root, jwks_str, arrlenu(jwks_str),
                   JSON_PRESERVE_ORDER | JSON_ENSURE_ASCII);
    } else {
        // null pointer error
        *err = ERR_NULL;
    }

    return jwks_str;
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
        if(jwks->root) {
            free(jwks->root);
            jwks->root = NULL;
        }
    }
}
