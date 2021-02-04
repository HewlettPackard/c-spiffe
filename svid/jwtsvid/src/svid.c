#include <cjose/cjose.h>
#include "svid.h"
#include "../../../bundle/jwtbundle/src/source.h"

//one minute leeway
time_t DEFAULT_LEEWAY = 60L;

jwtbundle_Source *__bundles;

typedef struct 
{
    json_t *header;
    json_t *payload;
    string_t header_str;
    string_t payload_str;
    string_t signature;
} jwtsvid_JWT;

typedef struct
{
    string_t issuer;
    string_t subject;
    string_arr_t audience;
    time_t expiry;
    time_t not_before;
    time_t issued_at;
    string_t id;
} jwtsvid_Claims;

typedef map_string_claim* (*token_validator_t)(jwtsvid_JWT*, 
                                            spiffeid_TrustDomain, 
                                            err_t*);

static jwtsvid_JWT* token_to_jwt(char *token, err_t *err)
{
    if(token)
    {
        const char dot[] = ".";
        const char *header = strtok(token, dot);
        if(!empty_str(header))
        {
            string_t header_new = string_new(header);
            uint8_t *header_str = NULL;
            size_t header_str_len;
            cjose_base64url_decode(header, 
                                strlen(header), 
                                &header_str,
                                &header_str_len,
                                NULL);
            const char *payload = strtok(NULL, dot);
            
            if(!empty_str(payload))
            {
                string_t payload_new = string_new(payload);
                uint8_t *payload_str = NULL;
                size_t payload_str_len;
                cjose_base64url_decode(payload,
                                    strlen(payload),
                                    &payload_str,
                                    &payload_str_len,
                                    NULL);

                jwtsvid_JWT *jwt = malloc(sizeof *jwt);
                jwt->header_str = header_new;
                jwt->payload_str = payload_new;
                jwt->header = json_loadb((const char*) header_str, 
                                        header_str_len, 
                                        0, 
                                        NULL);
                jwt->payload = json_loadb((const char*) payload_str, 
                                        payload_str_len,
                                        0, 
                                        NULL);
                jwt->signature = string_new(strtok(NULL, dot));
                free(header_str);
                free(payload_str);
                
                if(jwt->header && jwt->payload && jwt->signature)
                {
                    //everything was parsed correctly
                    *err = NO_ERROR;
                    return jwt;
                }
                //error parsing
                *err = ERROR3;
                return NULL;
            }
            arrfree(header_new);
        }
        //header or payload are empty     
        *err = ERROR2;
        return NULL;
    }
    //token is null
    *err = ERROR1;
    return NULL;
}

static err_t validate_jwt(jwtsvid_JWT *jwt, EVP_PKEY *pkey)
{
    if(jwt)
    {
        json_t *alg_json = json_object_get(jwt->header, "alg");
        const char *alg_str = json_typeof(alg_json) == JSON_STRING?
            json_string_value(alg_json) : NULL;

        if(alg_str)
        {
            int sha_alg_num = 0;
            sscanf(alg_str, "%*c%*c%d", &sha_alg_num);
            
            const EVP_MD* (*sha_alg)(void) = NULL;
            if(sha_alg_num == 256) sha_alg = EVP_sha256;
            else if(sha_alg_num == 384) sha_alg = EVP_sha384;
            else if(sha_alg_num == 512) sha_alg = EVP_sha512;

            if(sha_alg)
            {
                EVP_MD_CTX *ctx = EVP_MD_CTX_new();
                EVP_DigestVerifyInit(ctx, NULL, sha_alg(), NULL, pkey);
                
                string_t md = string_new(jwt->header_str);
                md = string_push(md, ".");
                md = string_push(md, jwt->payload_str);
                const int ret = EVP_DigestVerify(ctx, 
                                (const unsigned char*) jwt->signature, 
                                arrlenu(jwt->signature),
                                (const unsigned char*) md,
                                arrlenu(md));
                arrfree(md);

                if(ret > 0)
                    return NO_ERROR;
                //the signature do not match the MD
                return ERROR4;
            }
            //invalid algorithm
            return ERROR3;
        }
        //could not get algorithm field
        return ERROR2;
    }
    //jwt is NULL
    return ERROR1;
}

static void jwtsvid_JWT_Free(jwtsvid_JWT *jwt)
{
    if(jwt)
    {
        free(jwt->header);
        free(jwt->payload);
        arrfree(jwt->header_str);
        arrfree(jwt->payload_str);
        arrfree(jwt->signature);
        free(jwt);
    }
}

static void jwtsvid_Claims_Free(jwtsvid_Claims *claims)
{
    if(claims)
    {
        arrfree(claims->issuer);
        arrfree(claims->subject);
        arrfree(claims->id);
        for(size_t i = 0, size = arrlenu(claims->audience); i < size; ++i)
        {
            arrfree(claims->audience[i]);
        }
        arrfree(claims->audience);
    }
}

static map_string_claim* json_to_map(json_t *obj)
{
    if(obj)
    {
        if(json_typeof(obj) == JSON_OBJECT)
        {
            const char *key;
            json_t *value;
            map_string_claim *claims_map = NULL;

            json_object_foreach(obj, key, value)
            {
                shput(claims_map, key, value);
            }

            return claims_map;
        }
    }

    return NULL;
}

static map_string_claim* parseAndValidate(jwtsvid_JWT *jwt,
                                        spiffeid_TrustDomain td,
                                        err_t *err)
{
    if(jwt)
    {
        json_t *kid_json = json_object_get(jwt->header, "kid");
        const char *kid_str = json_typeof(kid_json) == JSON_STRING?
            json_string_value(kid_json) : NULL;

        if(!empty_str(kid_str))
        {
            jwtbundle_Bundle *bundle = 
                jwtbundle_Source_GetJWTBundleForTrustDomain(
                    __bundles, td, err);
            if(*err)
            {
                //could not find bundle for given trust domain
                *err = ERROR3;
                return NULL;
            }

            bool suc;
            EVP_PKEY *pkey = 
                jwtbundle_Bundle_FindJWTAuthority(bundle, kid_str, &suc);

            if(suc)
            {
                if(!validate_jwt(jwt, pkey))
                {
                    map_string_claim *claims = json_to_map(jwt->payload);
                    if(claims)
                    {
                        *err = NO_ERROR;
                        return claims;
                    }
                    //error converting payload to a map
                    *err = ERROR6;
                    return NULL;
                }
                //not validated
                *err = ERROR5;
                return NULL;
            }
            //authority not found
            *err = ERROR4;
            return NULL;
        }
        //key id is empty or not found
        *err = ERROR2;
        return NULL;
    }
    //jwt is NULL
    *err = ERROR1;
    return NULL;
}

static map_string_claim* parseInsecure(jwtsvid_JWT *jwt,
                                        spiffeid_TrustDomain td,
                                        err_t *err)
{
    if(jwt)
    {
        if(!(*err))
        {
            map_string_claim *claims = json_to_map(jwt->payload);
            if(claims)
            {
                *err = NO_ERROR;   
                return claims;
            }
            //payload is not an json object
            *err = ERROR3;
            return NULL;
        }
        //could not decode token
        *err = ERROR2;
        return NULL;
    }
    //jwt is NULL
    *err = ERROR1;
    return NULL;
}

static jwtsvid_Claims* json_to_claims(json_t *obj)
{
    if(obj)
    {
        if(json_typeof(obj) == JSON_OBJECT)
        {
            json_t *issuer_json = json_object_get(obj, "iss");
            json_t *subject_json = json_object_get(obj, "sub");
            json_t *id_json = json_object_get(obj, "jti");
            json_t *expiry_json = json_object_get(obj, "exp");
            json_t *notbefore_json = json_object_get(obj, "nbf");
            json_t *issuedat_json = json_object_get(obj, "iat");
            json_t *audience_json = json_object_get(obj, "aud");

            jwtsvid_Claims *claims = malloc(sizeof *claims);
            claims->issuer = json_typeof(issuer_json) == JSON_STRING?
                string_new(json_string_value(issuer_json)) : NULL;
            claims->subject = json_typeof(subject_json) == JSON_STRING?
                string_new(json_string_value(subject_json)) : NULL;
            claims->id = json_typeof(id_json) == JSON_STRING?
                string_new(json_string_value(id_json)) : NULL;
            claims->expiry = json_typeof(expiry_json) == JSON_INTEGER?
                (time_t) json_integer_value(expiry_json) : -1;
            claims->not_before = json_typeof(notbefore_json) == JSON_INTEGER?
                (time_t) json_integer_value(notbefore_json) : -1;
            claims->issued_at = json_typeof(issuedat_json) == JSON_INTEGER?
                (time_t) json_integer_value(issuedat_json) : -1;
            claims->audience = NULL;
            if(json_typeof(audience_json) == JSON_ARRAY)
            {
                size_t i;
                json_t *value;
                json_array_foreach(audience_json, i, value)
                {
                    if(json_typeof(value) == JSON_STRING)
                    {
                        arrput(claims->audience, 
                            string_new(json_string_value(value)));
                    }
                }
            }
            else if(json_typeof(audience_json) == JSON_STRING)
            {
                arrput(claims->audience, 
                    string_new(json_string_value(audience_json)));
            }
        
            return claims;
        }
    }

    return NULL;
}

static bool strarr_contains(string_arr_t arr, string_t str)
{
    for(size_t i = 0, size = arrlenu(arr); i < size; ++i)
    {
        if(!strcmp(arr[i], str))
            return true;
    }

    return false;
}

static err_t validate_claims(jwtsvid_Claims *claims, string_arr_t audience)
{
    if(claims)
    {
        time_t now = time(NULL);

        for(size_t i = 0, size1 = arrlenu(audience); i < size1; ++i)
        {
            if(!strarr_contains(claims->audience, audience[i]))
            {
                //invalid audience
                return ERROR2;
            }
        }

        if(claims->expiry > 0 && claims->expiry < now - DEFAULT_LEEWAY)
        {
            //expired
            return ERROR3;
        }
        else if(claims->not_before > 0 && claims->not_before > now + DEFAULT_LEEWAY)
        {
            //not valid yet
            return ERROR4;
        }
        else if(claims->issued_at > 0 && claims->issued_at > now + DEFAULT_LEEWAY)
        {
            //issued in the future
            return ERROR5;
        }

        return NO_ERROR;
    }
    //claims is NULL
    return ERROR1;
}

jwtsvid_SVID* jwtsvid_ParseAndValidate(char *token, 
                                        jwtbundle_Source *bundles,
                                        string_arr_t audience,
                                        err_t *err)
{
    __bundles = bundles;
    return jwtsvid_parse(token, audience, parseAndValidate, err);
}

jwtsvid_SVID* jwtsvid_ParseInsecure(char *token, 
                                    string_arr_t audience, 
                                    err_t *err)
{
    return jwtsvid_parse(token, audience, parseInsecure, err);
}

string_t jwtsvid_SVID_Marshal(jwtsvid_SVID *svid)
{
    if(svid) return svid->token;
    return NULL;
}

jwtsvid_SVID* jwtsvid_parse(char *token, 
                            string_arr_t audience, 
                            token_validator_t validator, 
                            err_t *err)
{
    jwtsvid_JWT *jwt = NULL;
    jwtsvid_Claims *claims = NULL;
    if(token)
    {
        err_t err2;
        jwt = token_to_jwt(token, &err2);

        if(!err2)
        {
            err2 = jwtsvid_validateTokenAlgorithm(jwt);

            if(!err2)
            {
                claims = json_to_claims(jwt->payload);

                if(empty_str(claims->subject) || claims->expiry <= 0)
                {
                    //either subject or expiry are missing
                    *err = ERROR3;
                    goto ret;
                }

                spiffeid_ID id = spiffeid_FromString(claims->subject, &err2);
                if(err2)
                {
                    //subject claim is not a valid spiffe id
                    *err = ERROR4;
                    goto ret;
                }

                map_string_claim *claims_map = validator(jwt, (spiffeid_TrustDomain){NULL}, &err2);
                if(err2)
                {
                    //could not validate jwt object
                    *err = ERROR5;
                    goto ret;
                }

                err2 = validate_claims(claims, audience);
                if(err2)
                {
                    //claims not valid
                    *err = ERROR6;
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
                
                return svid;
            }
        }
        //unable to parse token
        *err = ERROR2;
        goto ret;
    }
    //token is NULL
    *err = ERROR1;
ret:
    jwtsvid_JWT_Free(jwt);
    jwtsvid_Claims_Free(claims);
    return NULL;
}

err_t jwtsvid_validateTokenAlgorithm(jwtsvid_JWT *jwt)
{
    if(jwt)
    {
        if(json_typeof(jwt->header) == JSON_OBJECT)
        {
            json_t *alg_json = json_object_get(jwt->header, "alg");
            const char *alg_str = json_string_value(alg_json);
            
            const char *supported_algs[] = {
                CJOSE_HDR_ALG_RS256,
                CJOSE_HDR_ALG_RS384,
                CJOSE_HDR_ALG_RS512,
                CJOSE_HDR_ALG_ES256,
                CJOSE_HDR_ALG_ES384,
                CJOSE_HDR_ALG_ES512,
                CJOSE_HDR_ALG_PS256,
                CJOSE_HDR_ALG_PS384,
                CJOSE_HDR_ALG_PS512
            };
            const int size = (sizeof supported_algs) / (sizeof *supported_algs);
            
            for(int i = 0; i < size; ++i)
            {
                if(!strcmp(alg_str, supported_algs[i]))
                {
                    //supported algorithm
                    return NO_ERROR;
                }
            }
            //algorithm not supported
            return ERROR3;
        }
        //header is not a json object
        return ERROR2;
    }
    //jwt object is NULL
    return ERROR1;
}
