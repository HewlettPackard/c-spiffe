#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <cjose/jwk.h>
#include <json-c/json.h>
#include "../../../internal/jwtutil/include/util.h"
#include "../include/bundle.h"

jwtbundle_Bundle* jwtbundle_New(const spiffeid_TrustDomain td)
{
    jwtbundle_Bundle *bundleptr = malloc(sizeof *bundleptr);
    if(bundleptr)
    {
        bundleptr->td.name = string_push(NULL, td.name);
        bundleptr->auths = NULL;
        mtx_init(&(bundleptr->mtx), mtx_plain);
    }
    
    return bundleptr;
}

jwtbundle_Bundle* jwtbundle_FromJWTAuthorities(const spiffeid_TrustDomain td,
                                            const map_string_EVP_PKEY *auths)
{
    jwtbundle_Bundle *bundleptr = malloc(sizeof *bundleptr);
    if(bundleptr)
    {
        bundleptr->td.name = string_push(NULL, td.name);
        bundleptr->auths = jwtutil_CopyJWTAuthorities(auths);
        mtx_init(&(bundleptr->mtx), mtx_plain);
    }
    
    return bundleptr;
}

jwtbundle_Bundle* jwtbundle_Load(const spiffeid_TrustDomain td, 
                                            const string_t path, 
                                            err_t *err)
{
    jwtbundle_Bundle *bundleptr = NULL;
    FILE *fjwks = fopen(path, "r");
    if(fjwks)
    {
        //go to the end of the file
        fseek(fjwks, 0, SEEK_END);
        //get length in bytes
        long int flen = ftell(fjwks);
        //return to the beginning
        rewind(fjwks);
        
        string_t buffer = NULL;
        //set byte array capacity
        arrsetcap(buffer, flen);
        //read bytes into buffer
        fread(buffer, flen, 1, fjwks);
        fclose(fjwks);
        //string end
        // arrput(buffer, (byte) 0);
        bundleptr = jwtbundle_Parse(td, buffer, err);
        arrfree(buffer);
    }
    else
        *err = ERROR1;
    
    return bundleptr;
}

/*jwtbundle_Bundle* jwtbundle_Read(const spiffeid_TrustDomain td, 
                                            void *reader,   //Fix 
                                            err_t *err)
{
    //dummy
    return NULL;
}*/

jwtbundle_Bundle* jwtbundle_Parse(const spiffeid_TrustDomain td, 
                                            const string_t bundle_bytes, 
                                            err_t *err)
{

    jwtbundle_Bundle *bundle = jwtbundle_New(td);    

    struct json_object *parsed_json = json_tokener_parse(bundle_bytes);
    struct json_object *keys = NULL;
    json_object_object_get_ex(parsed_json, "keys", &keys);
    const size_t n_keys = json_object_array_length(keys);

    for(size_t i = 0; i < n_keys; ++i)
    {
        ///TODO: check if this is correct

        //get i-th element of the JWKS
        struct json_object *elem_obj = 
            json_object_array_get_idx(keys, i);
        //get string related to the item
        const char *key_str = 
            json_object_get_string(elem_obj);
        cjose_err cj_err;
        //parse the raw bytes into a JWK object
        const cjose_jwk_t *jwk = 
            cjose_jwk_import(key_str, strlen(key_str), &cj_err);
        //get kid field
        const char *kid = 
            cjose_jwk_get_kid(jwk, &cj_err);
        //get key type
        const cjose_jwk_kty_t kty = 
            cjose_jwk_get_kty(jwk, &cj_err);
        //get key data
        void *keydata = 
            cjose_jwk_get_keydata(jwk, &cj_err);
        //get key size
        const long keysize = 
            cjose_jwk_get_keysize(jwk, &cj_err);
        EVP_PKEY *pkey = EVP_PKEY_new();
        RSA *rsa_key = NULL;
        EC_KEY *ec_key = EC_KEY_new();

        switch(kty)
        {
        case CJOSE_JWK_KTY_RSA:
            rsa_key = d2i_RSA_PUBKEY(NULL, (const byte**) &keydata, keysize);
            EVP_PKEY_assign_RSA(pkey, rsa_key);
            break;
        case CJOSE_JWK_KTY_EC:
            EC_KEY_oct2key(ec_key, (const byte*) keydata, keysize, NULL);
            EVP_PKEY_assign_EC_KEY(pkey, ec_key);
            break;
        default:
            //type not supported currently
            break;
        }
        
        RSA_free(rsa_key);
        EC_KEY_free(ec_key);

        if(pkey)
        {
            //insert id and its public on the map
            shput(bundle->auths, kid, pkey);
        }
    }
    
    return bundle;
}
                                            
const spiffeid_TrustDomain jwtbundle_Bundle_TrustDomain(const jwtbundle_Bundle *b)
{
    return b->td;
}

map_string_EVP_PKEY* jwtbundle_Bundle_JWTAuthorities(jwtbundle_Bundle *b)
{
    mtx_lock(&(b->mtx));
    map_string_EVP_PKEY *copy_auths = jwtutil_CopyJWTAuthorities(b->auths);
    mtx_unlock(&(b->mtx));

    return copy_auths;
}

EVP_PKEY* jwtbundle_Bundle_FindJWTAuthority(jwtbundle_Bundle *b,
                                            const string_t keyID, 
                                            bool *suc)
{
    mtx_lock(&(b->mtx));
    EVP_PKEY *pkey = NULL;
    *suc = false;
    map_string_EVP_PKEY *key_val = shgetp_null(b->auths, keyID);
    if(key_val)
    {
        pkey = key_val->value;
        *suc = true;
    }
    mtx_unlock(&(b->mtx));

    return pkey;
}

bool jwtbundle_Bundle_HasJWTAuthority(jwtbundle_Bundle *b, 
                                        const string_t keyID)
{
    mtx_lock(&(b->mtx));
    bool present = false;
    int idx = shgeti(b->auths, keyID);
    if(idx >= 0) present = true;
    mtx_unlock(&(b->mtx));

    return present;
}

err_t jwtbundle_Bundle_AddJWTAuthority(jwtbundle_Bundle *b,
                                        const string_t keyID,
                                        EVP_PKEY *pkey)
{
    //empty string error
    err_t err = ERROR1;

    if(!empty_str(keyID))
    {
        mtx_lock(&(b->mtx));
        shput(b->auths, keyID, pkey);
        err = NO_ERROR;
        mtx_unlock(&(b->mtx));
    }

    return err;
}

void jwtbundle_Bundle_RemoveJWTAuthority(jwtbundle_Bundle *b, 
                                            const string_t keyID)
{
    mtx_lock(&(b->mtx));
    shdel(b->auths, keyID);
    mtx_unlock(&(b->mtx));
}

void jwtbundle_Bundle_SetJWTAuthorities(jwtbundle_Bundle *b,
                                        const map_string_EVP_PKEY *auths)
{
    mtx_lock(&(b->mtx));
    ///TODO: check if it is needed to free the EVP_PKEY objs
    shfree(b->auths);
    b->auths = jwtutil_CopyJWTAuthorities(auths);
    mtx_unlock(&(b->mtx));
}

bool jwtbundle_Bundle_Empty(jwtbundle_Bundle *b)
{
    mtx_lock(&(b->mtx));
    bool empty = (shlenu(b->auths) == 0);
    mtx_unlock(&(b->mtx));

    return empty;
}

byte* jwtbundle_Bundle_Marshal(jwtbundle_Bundle *b, err_t *err)
{
    //dummy
    return NULL;
}

jwtbundle_Bundle* jwtbundle_Bundle_Clone(jwtbundle_Bundle *b)
{
    mtx_lock(&(b->mtx));
    jwtbundle_Bundle *bundle = jwtbundle_FromJWTAuthorities(b->td, b->auths);
    mtx_unlock(&(b->mtx));

    return bundle;
}

bool jwtbundle_Bundle_Equal(const jwtbundle_Bundle *b1, 
                            const jwtbundle_Bundle *b2)
{
    if(b1 || b2)
    {
        //equal trust domains and equal JWT authorities
        return !strcmp(b1->td.name, b2->td.name) &&
            jwtutil_JWTAuthoritiesEqual(b1->auths, b2->auths);
    }
    else
        return b1 == b2;
}

jwtbundle_Bundle* jwtbundle_Bundle_GetJWTBundleForTrustDomain(
                                            jwtbundle_Bundle *b,
                                            const spiffeid_TrustDomain td,
                                            err_t *err)
{
    mtx_lock(&(b->mtx));
    jwtbundle_Bundle *bundle = NULL;
    //different trust domains error
    *err = ERROR1;
    //if the TDs are equal
    if(!strcmp(b->td.name, td.name))
    {
        bundle = b;
        *err = NO_ERROR;
    }
    mtx_unlock(&(b->mtx));

    return bundle;
}