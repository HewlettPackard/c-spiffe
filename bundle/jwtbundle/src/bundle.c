#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <cjose/jwk.h>
#include <jansson.h>
#include "../../../internal/jwtutil/src/util.h"
#include "../../../spiffeid/src/trustdomain.h"
#include "bundle.h"

typedef struct _ec_keydata_int
{
    cjose_jwk_ec_curve crv;
    EC_KEY *key;
} ec_keydata;

jwtbundle_Bundle* jwtbundle_New(const spiffeid_TrustDomain td)
{
    jwtbundle_Bundle *bundleptr = malloc(sizeof *bundleptr);
    if(bundleptr)
    {
        bundleptr->td.name = string_new(td.name);
        bundleptr->auths = NULL;
        mtx_init(&(bundleptr->mtx), mtx_plain);
    }
    
    return bundleptr;
}

jwtbundle_Bundle* jwtbundle_FromJWTAuthorities(const spiffeid_TrustDomain td,
                                                map_string_EVP_PKEY *auths)
{
    jwtbundle_Bundle *bundleptr = malloc(sizeof *bundleptr);
    if(bundleptr)
    {
        bundleptr->td.name = string_new(td.name);
        bundleptr->auths = jwtutil_CopyJWTAuthorities(auths);
        mtx_init(&(bundleptr->mtx), mtx_plain);
    }
    
    return bundleptr;
}

jwtbundle_Bundle* jwtbundle_Load(const spiffeid_TrustDomain td, 
                                    const char *path, 
                                    err_t *err)
{
    jwtbundle_Bundle *bundleptr = NULL;
    FILE *fjwks = fopen(path, "r");
    if(fjwks)
    {
        string_t buffer = FILE_to_string(fjwks);
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

jwtbundle_Bundle* jwtbundle_Parse(const spiffeid_TrustDomain td, 
                                    const string_t bundle_bytes, 
                                    err_t *err)
{

    jwtbundle_Bundle *bundle = jwtbundle_New(td);    

    json_error_t j_err;
    json_t *root = json_loads(bundle_bytes, 0, &j_err);
    json_t *keys = json_object_get(root, "keys");
    const size_t n_keys = json_array_size(keys);

    *err = NO_ERROR;
    
    for(size_t i = 0; i < n_keys; ++i)
    {
        //get i-th element of the JWKS

        json_t *elem_obj = json_array_get(keys, i);
        const char *key_str = json_dumps(elem_obj, 0);

        cjose_err cj_err;
        //parse the raw bytes into a JWK object
        const cjose_jwk_t *jwk = 
            cjose_jwk_import(key_str, strlen(key_str), &cj_err);
        //get key id field
        const char *kid = 
            cjose_jwk_get_kid(jwk, &cj_err);
        //get key type
        const cjose_jwk_kty_t kty = 
            cjose_jwk_get_kty(jwk, &cj_err);
        //get key data
        void *keydata = 
            cjose_jwk_get_keydata(jwk, &cj_err);
        //get key size in bits
        // const long keysize = 
        //     cjose_jwk_get_keysize(jwk, &cj_err);
        EVP_PKEY *pkey = EVP_PKEY_new();
        
        switch(kty)
        {
        case CJOSE_JWK_KTY_RSA:
            EVP_PKEY_set1_RSA(pkey, (RSA*) keydata);
            break;
        case CJOSE_JWK_KTY_EC:
            EVP_PKEY_set1_EC_KEY(pkey, ((ec_keydata*) keydata)->key);
            break;
        default:
            //type not supported currently
            ///TODO: handle unexpected key type
            break;
        }

        if(pkey)
        {
            //insert id and its public key on the map
            shput(bundle->auths, kid, pkey);
        }
    }
    
    return bundle;
}
                                            
spiffeid_TrustDomain jwtbundle_Bundle_TrustDomain(const jwtbundle_Bundle *b)
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
                                            const char *keyID, 
                                            bool *suc)
{
    mtx_lock(&(b->mtx));
    EVP_PKEY *pkey = NULL;
    *suc = false;
    const int idx = shgeti(b->auths, keyID);
    if(idx >= 0)
    {
        pkey = b->auths[idx].value;
        *suc = true;
    }
    mtx_unlock(&(b->mtx));

    return pkey;
}

bool jwtbundle_Bundle_HasJWTAuthority(jwtbundle_Bundle *b, 
                                        const char *keyID)
{
    mtx_lock(&(b->mtx));
    const bool present = shgeti(b->auths, keyID) >= 0? true : false;
    mtx_unlock(&(b->mtx));

    return present;
}

err_t jwtbundle_Bundle_AddJWTAuthority(jwtbundle_Bundle *b,
                                        const char *keyID,
                                        EVP_PKEY *pkey)
{
    //empty string error
    err_t err = ERROR1;

    if(!empty_str(keyID))
    {
        mtx_lock(&(b->mtx));
        EVP_PKEY_up_ref(pkey);
        shput(b->auths, keyID, pkey);
        err = NO_ERROR;
        mtx_unlock(&(b->mtx));
    }

    return err;
}

void jwtbundle_Bundle_RemoveJWTAuthority(jwtbundle_Bundle *b, 
                                            const char *keyID)
{
    mtx_lock(&(b->mtx));
    int idx = shgeti(b->auths, keyID);
    const bool present = idx >= 0? true : false;
    if(present)
    {   
        EVP_PKEY_free(b->auths[idx].value);
        shdel(b->auths, keyID);
    }
    mtx_unlock(&(b->mtx));
}

void jwtbundle_Bundle_SetJWTAuthorities(jwtbundle_Bundle *b,
                                        map_string_EVP_PKEY *auths)
{
    mtx_lock(&(b->mtx));
    for(size_t i = 0, size = shlenu(b->auths); i < size; ++i)
    {
        EVP_PKEY_free(b->auths[i].value);
    }
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
    if(b1 && b2)
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

void jwtbundle_Bundle_Free(jwtbundle_Bundle *b, bool alloc)
{
    if(b)
    {
        // mtx_destroy(&(b->mtx));
        for(size_t i = 0, size = shlenu(b->auths); i < size; ++i)
        {
            EVP_PKEY_free(b->auths[i].value);
        }
        shfree(b->auths);
        spiffeid_TrustDomain_Free(&(b->td), false);

        if(alloc)
        {
            free(b);
        }
    }
}