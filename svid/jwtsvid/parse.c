#include "c-spiffe/svid/jwtsvid/parse.h"
#include "c-spiffe/bundle/jwtbundle/source.h"
#include <cjose/cjose.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <time.h>

// one minute leeway
const time_t DEFAULT_LEEWAY = 60L;

typedef struct {
    string_t issuer;
    string_t subject;
    string_arr_t audience;
    time_t expiry;
    time_t not_before;
    time_t issued_at;
    string_t id;
} jwtsvid_Claims;

static void jwtsvid_JWT_Free(jwtsvid_JWT *jwt)
{
    if(jwt) {
        free(jwt->header);
        free(jwt->payload);
        arrfree(jwt->header_str);
        arrfree(jwt->payload_str);
        arrfree(jwt->signature);

        free(jwt);
    }
}

static jwtsvid_JWT *token_to_jwt(char *token, err_t *err)
{
    if(token) {
        const char dot[] = ".";
        const char *header = strtok(token, dot);
        if(!empty_str(header)) {
            string_t header_new = string_new(header);
            uint8_t *header_str = NULL;
            size_t header_str_len;
            cjose_base64url_decode(header, strlen(header), &header_str,
                                   &header_str_len, NULL);
            char *payload = strtok(NULL, dot);
            payload[-1] = '.';

            if(!empty_str(payload)) {
                string_t payload_new = string_new(payload);
                uint8_t *payload_str = NULL;
                size_t payload_str_len;
                cjose_base64url_decode(payload, strlen(payload), &payload_str,
                                       &payload_str_len, NULL);

                jwtsvid_JWT *jwt = malloc(sizeof *jwt);
                jwt->header_str = header_new;
                jwt->payload_str = payload_new;
                jwt->header = json_loadb((const char *) header_str,
                                         header_str_len, 0, NULL);
                jwt->payload = json_loadb((const char *) payload_str,
                                          payload_str_len, 0, NULL);

                char *signature = strtok(NULL, dot);
                signature[-1] = '.';
                jwt->signature = string_new(signature);
                free(header_str);
                free(payload_str);

                if(jwt->header && jwt->payload && jwt->signature) {
                    // everything was parsed correctly
                    *err = NO_ERROR;
                    return jwt;
                }
                // error parsing
                jwtsvid_JWT_Free(jwt);
                *err = ERR_PARSING;
                return NULL;
            }
            arrfree(header_new);
            free(header_str);
        }
        // header or payload are empty
        *err = ERR_EMPTY_DATA;
        return NULL;
    }
    // token is null
    *err = ERR_NULL_TOKEN;
    return NULL;
}

static string_t ec_sig_to_as1n(const uint8_t *sig, size_t len, unsigned deg,
                               bool *suc)
{
    const unsigned bn_len = (deg + 7) / 8;
    string_t ret_sig = NULL;
    *suc = false;
    if(2 * bn_len == len) {
        // get left side from signature
        BIGNUM *bn_r = BN_bin2bn(sig, bn_len, NULL);
        // get right side from signature
        BIGNUM *bn_s = BN_bin2bn(sig + bn_len, bn_len, NULL);

        // create a EC signature from EC point
        ECDSA_SIG *ec_sig = ECDSA_SIG_new();
        ECDSA_SIG_set0(ec_sig, bn_r, bn_s);

        // get length to reserve on string
        int sig_len = i2d_ECDSA_SIG(ec_sig, NULL);

        if(sig_len > 0) {
            arrsetlen(ret_sig, sig_len);
            unsigned char *p_out = (unsigned char *) ret_sig;

            // convert EC signature to DER format
            i2d_ECDSA_SIG(ec_sig, &p_out);
            *suc = true;
        }

        ECDSA_SIG_free(ec_sig);
    }

    return ret_sig;
}

static err_t validate_jwt(jwtsvid_JWT *jwt, EVP_PKEY *pkey)
{
    if(jwt) {
        json_t *alg_json = json_object_get(jwt->header, "alg");

        const char *alg_str = NULL;
        if(alg_json)
            alg_str = json_typeof(alg_json) == JSON_STRING
                          ? json_string_value(alg_json)
                          : NULL;

        if(alg_str) {
            int sha_alg_num = 0;
            sscanf(alg_str, "%*c%*c%d", &sha_alg_num);

            const EVP_MD *(*sha_alg)(void) = NULL;
            if(sha_alg_num == 256)
                sha_alg = EVP_sha256;
            else if(sha_alg_num == 384)
                sha_alg = EVP_sha384;
            else if(sha_alg_num == 512)
                sha_alg = EVP_sha512;

            if(sha_alg) {
                EVP_MD_CTX *ctx = EVP_MD_CTX_new();

                const int init
                    = EVP_DigestVerifyInit(ctx, NULL, sha_alg(), NULL, pkey);
                if(init != 1) {
                    EVP_MD_CTX_free(ctx);
                    // could not initialize ctx with public key
                    return ERR_INITIALIZING;
                }

                string_t md = string_new(jwt->header_str);
                md = string_push(md, ".");
                md = string_push(md, jwt->payload_str);

                uint8_t *buffer;
                size_t buffer_size;
                cjose_base64url_decode(jwt->signature, strlen(jwt->signature),
                                       &buffer, &buffer_size, NULL);

                int ret = EVP_DigestVerifyUpdate(
                    ctx, (const unsigned char *) md, strlen(md));
                if(ret != 1) {
                    EVP_MD_CTX_free(ctx);
                    arrfree(md);
                    free(buffer);
                    // could not initialize ctx with message digest
                    return ERR_INITIALIZING;
                }

                const int key_type = EVP_PKEY_base_id(pkey);

                if(key_type == EVP_PKEY_RSA) {
                    ret = EVP_DigestVerifyFinal(
                        ctx, (const unsigned char *) buffer, buffer_size);
                } else if(key_type == EVP_PKEY_EC) {
                    EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
                    const int deg
                        = EC_GROUP_get_degree(EC_KEY_get0_group(ec_key));

                    bool suc;
                    string_t sig
                        = ec_sig_to_as1n(buffer, buffer_size, deg, &suc);
                    if(suc && sig) {
                        ret = EVP_DigestVerifyFinal(
                            ctx, (const unsigned char *) sig, arrlenu(sig));
                    } else {
                        ret = 0;
                    }
                    arrfree(sig);
                }

                EVP_MD_CTX_free(ctx);
                arrfree(md);
                free(buffer);

                if(ret == 1)
                    return NO_ERROR;
                // the signature does not match the MD
                return ERR_UNMATCH;
            }
            // invalid algorithm
            return ERR_INVALID_ALGORITHM;
        }
        // could not get algorithm field
        return ERR_INVALID_DATA;
    }
    // jwt is NULL
    return ERR_NULL_JWT;
}

static void jwtsvid_Claims_Free(jwtsvid_Claims *claims)
{
    if(claims) {
        arrfree(claims->issuer);
        arrfree(claims->subject);
        arrfree(claims->id);
        for(size_t i = 0, size = arrlenu(claims->audience); i < size; ++i) {
            arrfree(claims->audience[i]);
        }
        arrfree(claims->audience);
    }
}

static map_string_claim *json_to_map(json_t *obj)
{
    if(obj) {
        if(json_typeof(obj) == JSON_OBJECT) {
            const char *key;
            json_t *value;
            map_string_claim *claims_map = NULL;
            sh_new_strdup(claims_map);

            json_object_foreach(obj, key, value)
            {
                shput(claims_map, key, value);
            }

            return claims_map;
        }
    }

    return NULL;
}

static map_string_claim *parseAndValidate(jwtsvid_JWT *jwt,
                                          spiffeid_TrustDomain td, void *arg,
                                          err_t *err)
{
    if(jwt) {
        json_t *kid_json = json_object_get(jwt->header, "kid");
        json_t *type_json = json_object_get(jwt->header, "typ");

        const char *kid_str = NULL;
        bool type_correct = true;
        if(kid_json) {
            kid_str = json_typeof(kid_json) == JSON_STRING
                          ? json_string_value(kid_json)
                          : NULL;
        }
        if(type_json) {
            const char *type_str = json_typeof(type_json) == JSON_STRING
                                       ? json_string_value(type_json)
                                       : NULL;
            if(type_str) {
                if(strcmp(type_str, "JWT") != 0
                   && strcmp(type_str, "JOSE") != 0) {
                    type_correct = false;
                }
            }
        }

        if(!empty_str(kid_str) && type_correct) {
            jwtbundle_Source *bundles = arg;
            jwtbundle_Bundle *bundle
                = jwtbundle_Source_GetJWTBundleForTrustDomain(bundles, td,
                                                              err);
            if(*err) {
                // could not find bundle for given trust domain
                *err = ERR_NOT_FOUND;
                return NULL;
            }

            bool suc;
            EVP_PKEY *pkey
                = jwtbundle_Bundle_FindJWTAuthority(bundle, kid_str, &suc);

            if(suc) {
                err_t err2 = validate_jwt(jwt, pkey);
                if(!err2) {
                    map_string_claim *claims = json_to_map(jwt->payload);
                    if(claims) {
                        *err = NO_ERROR;
                        return claims;
                    }
                    // error converting payload to a map
                    *err = ERR_PARSING;
                    return NULL;
                }
                // not validated
                *err = ERR_INVALID_DATA;
                return NULL;
            }
            // authority not found
            *err = ERR_NOAUTHORITY;
            return NULL;
        }
        // key id is empty or type is incorrect
        *err = ERR_EMPTY_DATA;
        return NULL;
    }
    // jwt is NULL
    *err = ERR_NULL_JWT;
    return NULL;
}

static map_string_claim *parseInsecure(jwtsvid_JWT *jwt,
                                       spiffeid_TrustDomain td, void *unused,
                                       err_t *err)
{
    if(jwt) {
        map_string_claim *claims = json_to_map(jwt->payload);
        if(claims) {
            *err = NO_ERROR;
            return claims;
        }
        // payload is not a json object
        *err = ERR_PAYLOAD;
        return NULL;
    }
    // jwt is NULL
    *err = ERR_NULL_JWT;
    return NULL;
}

static jwtsvid_Claims *json_to_claims(json_t *obj)
{
    if(obj) {
        if(json_typeof(obj) == JSON_OBJECT) {
            json_t *issuer_json = json_object_get(obj, "iss");
            json_t *subject_json = json_object_get(obj, "sub");
            json_t *id_json = json_object_get(obj, "jti");
            json_t *expiry_json = json_object_get(obj, "exp");
            json_t *notbefore_json = json_object_get(obj, "nbf");
            json_t *issuedat_json = json_object_get(obj, "iat");
            json_t *audience_json = json_object_get(obj, "aud");

            jwtsvid_Claims *claims = malloc(sizeof *claims);
            memset(claims, 0, sizeof *claims);

            if(issuer_json)
                claims->issuer
                    = json_typeof(issuer_json) == JSON_STRING
                          ? string_new(json_string_value(issuer_json))
                          : NULL;
            if(subject_json)
                claims->subject
                    = json_typeof(subject_json) == JSON_STRING
                          ? string_new(json_string_value(subject_json))
                          : NULL;
            if(id_json)
                claims->id = json_typeof(id_json) == JSON_STRING
                                 ? string_new(json_string_value(id_json))
                                 : NULL;
            if(expiry_json)
                claims->expiry = json_typeof(expiry_json) == JSON_INTEGER
                                     ? (time_t) json_integer_value(expiry_json)
                                     : -1;
            if(notbefore_json)
                claims->not_before
                    = json_typeof(notbefore_json) == JSON_INTEGER
                          ? (time_t) json_integer_value(notbefore_json)
                          : -1;
            if(issuedat_json)
                claims->issued_at
                    = json_typeof(issuedat_json) == JSON_INTEGER
                          ? (time_t) json_integer_value(issuedat_json)
                          : -1;

            if(audience_json) {
                if(json_typeof(audience_json) == JSON_ARRAY) {
                    size_t i;
                    json_t *value;
                    json_array_foreach(audience_json, i, value)
                    {
                        if(json_typeof(value) == JSON_STRING) {
                            arrput(claims->audience,
                                   string_new(json_string_value(value)));
                        }
                    }
                } else if(json_typeof(audience_json) == JSON_STRING) {
                    arrput(claims->audience,
                           string_new(json_string_value(audience_json)));
                }
            }

            return claims;
        }
    }

    return NULL;
}

static bool strarr_contains(string_arr_t arr, string_t str)
{
    for(size_t i = 0, size = arrlenu(arr); i < size; ++i) {
        if(!strcmp(arr[i], str))
            return true;
    }

    return false;
}

static err_t validate_claims(jwtsvid_Claims *claims, string_arr_t audience)
{
    if(claims) {
        time_t now = time(NULL);

        for(size_t i = 0, size = arrlenu(audience); i < size; ++i) {
            if(!strarr_contains(claims->audience, audience[i])) {
                // invalid audience
                return ERR_INVALID_DATA;
            }
        }

        if(claims->expiry > 0 && claims->expiry < now - DEFAULT_LEEWAY) {
            // expired
            return ERR_EXPIRED;
        } else if(claims->not_before > 0
                  && claims->not_before > now + DEFAULT_LEEWAY) {
            // not valid yet
            return ERR_INVALID_DATA;
        } else if(claims->issued_at > 0
                  && claims->issued_at > now + DEFAULT_LEEWAY) {
            // issued in the future
            return ERR_DEFAULT;
        }

        return NO_ERROR;
    }
    // claims is NULL
    return ERR_NULL_CLAIMS;
}

static err_t jwtsvid_validateTokenAlgorithm(jwtsvid_JWT *jwt)
{
    if(jwt) {
        if(json_typeof(jwt->header) == JSON_OBJECT) {
            json_t *alg_json = json_object_get(jwt->header, "alg");
            const char *alg_str = json_string_value(alg_json);

            const char *supported_algs[] = {
                CJOSE_HDR_ALG_RS256, CJOSE_HDR_ALG_RS384, CJOSE_HDR_ALG_RS512,
                CJOSE_HDR_ALG_ES256, CJOSE_HDR_ALG_ES384, CJOSE_HDR_ALG_ES512,
                CJOSE_HDR_ALG_PS256, CJOSE_HDR_ALG_PS384, CJOSE_HDR_ALG_PS512
            };
            const int size
                = (sizeof supported_algs) / (sizeof *supported_algs);

            for(int i = 0; i < size; ++i) {
                if(!strcmp(alg_str, supported_algs[i])) {
                    // supported algorithm
                    return NO_ERROR;
                }
            }
            // algorithm not supported
            return ERR_INVALID_ALGORITHM;
        }
        // header is not a json object
        return ERR_INVALID_DATA;
    }
    // jwt object is NULL
    return ERR_NULL_JWT;
}

jwtsvid_SVID *jwtsvid_ParseAndValidate(char *token, jwtbundle_Source *bundles,
                                       string_arr_t audience, err_t *err)
{
    return jwtsvid_parse(token, audience, parseAndValidate, bundles, err);
}

jwtsvid_SVID *jwtsvid_ParseInsecure(char *token, string_arr_t audience,
                                    err_t *err)
{
    return jwtsvid_parse(token, audience, parseInsecure, NULL, err);
}

jwtsvid_SVID *jwtsvid_parse(char *token, string_arr_t audience,
                            token_validator_t validator, void *arg, err_t *err)
{
    jwtsvid_JWT *jwt = NULL;
    jwtsvid_Claims *claims = NULL;
    if(token) {
        err_t err2;
        jwt = token_to_jwt(token, &err2);

        if(!err2) {
            err2 = jwtsvid_validateTokenAlgorithm(jwt);

            if(!err2) {
                claims = json_to_claims(jwt->payload);

                if(empty_str(claims->subject) || claims->expiry <= 0) {
                    // either subject or expiry are missing
                    *err = ERR_INVALID_DATA;
                    goto ret;
                }

                spiffeid_ID id = spiffeid_FromString(claims->subject, &err2);

                if(err2) {
                    // subject claim is not a valid spiffe id
                    *err = ERR_INVALID_CLAIM;
                    goto ret;
                }

                map_string_claim *claims_map = NULL;
                sh_new_strdup(claims_map);

                if(validator)
                    claims_map = validator(jwt, spiffeid_ID_TrustDomain(id),
                                           arg, &err2);
                if(err2) {
                    // could not validate jwt object
                    *err = ERR_INVALID_JWT;
                    goto ret;
                }

                err2 = validate_claims(claims, audience);
                if(err2) {
                    // claims not valid
                    *err = ERR_INVALID_CLAIM;
                    goto ret;
                }

                jwtsvid_SVID *svid = malloc(sizeof *svid);
                svid->id = id;
                svid->audience = claims->audience;
                svid->expiry = claims->expiry;
                svid->claims = claims_map;
                svid->token = string_new(token);

                jwtsvid_JWT_Free(jwt);
                arrfree(claims->issuer);
                arrfree(claims->subject);
                arrfree(claims->id);

                *err = NO_ERROR;
                return svid;
            }
        }
        // unable to parse token
        *err = ERR_PARSING;
        goto ret;
    }
    // token is NULL
    *err = ERR_NULL_TOKEN;
ret:
    jwtsvid_JWT_Free(jwt);
    jwtsvid_Claims_Free(claims);
    return NULL;
}
