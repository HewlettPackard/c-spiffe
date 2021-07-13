#include "c-spiffe/bundle/jwtbundle/bundle.h"
#include "c-spiffe/internal/jwtutil/util.h"
#include "c-spiffe/spiffeid/trustdomain.h"
#include <cjose/jwk.h>
#include <jansson.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <stdio.h>

typedef struct _ec_keydata_int {
    cjose_jwk_ec_curve crv;
    EC_KEY *key;
} ec_keydata;

jwtbundle_Bundle *jwtbundle_New(const spiffeid_TrustDomain td)
{
    jwtbundle_Bundle *bundleptr = malloc(sizeof *bundleptr);
    if(bundleptr) {
        bundleptr->td.name = string_new(td.name);
        bundleptr->auths = NULL;
        sh_new_strdup(bundleptr->auths);
        mtx_init(&(bundleptr->mtx), mtx_plain);
    }

    return bundleptr;
}

jwtbundle_Bundle *jwtbundle_FromJWTAuthorities(const spiffeid_TrustDomain td,
                                               map_string_EVP_PKEY *auths)
{
    jwtbundle_Bundle *bundleptr = malloc(sizeof *bundleptr);
    if(bundleptr) {
        bundleptr->td.name = string_new(td.name);
        bundleptr->auths = jwtutil_CopyJWTAuthorities(auths);
        mtx_init(&(bundleptr->mtx), mtx_plain);
    }

    return bundleptr;
}

jwtbundle_Bundle *jwtbundle_Load(const spiffeid_TrustDomain td,
                                 const char *path, err_t *err)
{
    jwtbundle_Bundle *bundleptr = NULL;
    FILE *fjwks = fopen(path, "r");
    if(fjwks) {
        string_t buffer = FILE_to_string(fjwks);
        fclose(fjwks);
        bundleptr = jwtbundle_Parse(td, buffer, err);
        arrfree(buffer);
    } else
        *err = ERR_OPENING;

    return bundleptr;
}

jwtbundle_Bundle *jwtbundle_Parse(const spiffeid_TrustDomain td,
                                  const char *bundle_bytes, err_t *err)
{
    jwtbundle_Bundle *bundle = NULL;
    jwtutil_JWKS jwks = jwtutil_ParseJWKS(bundle_bytes, err);

    if(!(*err) && arrlenu(jwks.x509_auths) == 0) {
        bundle = jwtbundle_New(td);
        bundle->auths = jwks.jwt_auths;
    } else if(jwks.jwt_auths != NULL || jwks.x509_auths != NULL) {
        jwtutil_JWKS_Free(&jwks);
    }

    return bundle;
}

spiffeid_TrustDomain jwtbundle_Bundle_TrustDomain(const jwtbundle_Bundle *b)
{
    return b->td;
}

map_string_EVP_PKEY *jwtbundle_Bundle_JWTAuthorities(jwtbundle_Bundle *b)
{
    mtx_lock(&(b->mtx));
    map_string_EVP_PKEY *copy_auths = jwtutil_CopyJWTAuthorities(b->auths);
    mtx_unlock(&(b->mtx));

    return copy_auths;
}

EVP_PKEY *jwtbundle_Bundle_FindJWTAuthority(jwtbundle_Bundle *b,
                                            const char *keyID, bool *suc)
{
    mtx_lock(&(b->mtx));
    EVP_PKEY *pkey = NULL;
    *suc = false;
    const int idx = shgeti(b->auths, keyID);
    if(idx >= 0) {
        pkey = b->auths[idx].value;
        *suc = true;
    }
    mtx_unlock(&(b->mtx));

    return pkey;
}

bool jwtbundle_Bundle_HasJWTAuthority(jwtbundle_Bundle *b, const char *keyID)
{
    mtx_lock(&(b->mtx));
    const bool present = shgeti(b->auths, keyID) >= 0 ? true : false;
    mtx_unlock(&(b->mtx));

    return present;
}

err_t jwtbundle_Bundle_AddJWTAuthority(jwtbundle_Bundle *b, const char *keyID,
                                       EVP_PKEY *pkey)
{
    // empty string error
    err_t err = ERR_EMPTY_DATA;

    if(!empty_str(keyID)) {
        mtx_lock(&(b->mtx));
        if(shgeti(b->auths, keyID) < 0) {
            EVP_PKEY_up_ref(pkey);
            shput(b->auths, keyID, pkey);
        }
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
    const bool present = idx >= 0 ? true : false;
    if(present) {
        EVP_PKEY_free(b->auths[idx].value);
        shdel(b->auths, keyID);
    }
    mtx_unlock(&(b->mtx));
}

void jwtbundle_Bundle_SetJWTAuthorities(jwtbundle_Bundle *b,
                                        map_string_EVP_PKEY *auths)
{
    mtx_lock(&(b->mtx));
    for(size_t i = 0, size = shlenu(b->auths); i < size; ++i) {
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

jwtbundle_Bundle *jwtbundle_Bundle_Clone(jwtbundle_Bundle *b)
{
    mtx_lock(&(b->mtx));
    jwtbundle_Bundle *bundle = jwtbundle_FromJWTAuthorities(b->td, b->auths);
    mtx_unlock(&(b->mtx));

    return bundle;
}

bool jwtbundle_Bundle_Equal(const jwtbundle_Bundle *b1,
                            const jwtbundle_Bundle *b2)
{
    if(b1 && b2) {
        // equal trust domains and equal JWT authorities
        return !strcmp(b1->td.name, b2->td.name)
               && jwtutil_JWTAuthoritiesEqual(b1->auths, b2->auths);
    } else
        return b1 == b2;
}

jwtbundle_Bundle *jwtbundle_Bundle_GetJWTBundleForTrustDomain(
    jwtbundle_Bundle *b, const spiffeid_TrustDomain td, err_t *err)
{
    mtx_lock(&(b->mtx));
    jwtbundle_Bundle *bundle = NULL;
    // different trust domains error
    *err = ERR_INVALID_TRUSTDOMAIN;
    // if the TDs are equal
    if(!strcmp(b->td.name, td.name)) {
        bundle = b;
        *err = NO_ERROR;
    }
    mtx_unlock(&(b->mtx));

    return bundle;
}

void jwtbundle_Bundle_Free(jwtbundle_Bundle *b)
{
    if(b) {
        // mtx_destroy(&(b->mtx));
        for(size_t i = 0, size = shlenu(b->auths); i < size; ++i) {
            EVP_PKEY_free(b->auths[i].value);
        }
        shfree(b->auths);
        spiffeid_TrustDomain_Free(&(b->td));
        free(b);
    }
}

err_t jwtbundle_Bundle_print_BIO(jwtbundle_Bundle *b, int offset, BIO *out)
{
    if(offset < 0) {
        return ERR_BAD_REQUEST;
    } else if(b && out) {
        mtx_lock(&b->mtx); // lock the mutex so we guarantee no one changes
                           // things before we print.

        BIO_indent(out, offset, 20);
        BIO_printf(out, "Trust Domain: %s\n", b->td.name);
        BIO_indent(out, offset, 20);
        BIO_printf(out, "Keys: [\n");

        for(size_t i = 0, size = shlenu(b->auths); i < size; ++i) {
            // print using ssl functions.
            BIO_indent(out, offset + 1, 20);
            BIO_printf(out, "kID: \"%s\" {\n", b->auths[i].key);

            EVP_PKEY_print_public(out, b->auths[i].value, offset + 2, NULL);

            BIO_indent(out, offset + 1, 20);
            BIO_printf(out, "}\n");
        }

        BIO_indent(out, offset, 20);
        BIO_printf(out, "]\n");

        mtx_unlock(&b->mtx); // unlock bundle mutex.
        return NO_ERROR;
    } else if(!b) {
        return ERR_NULL_DATA;
    } else {
        return ERR_NULL_BUNDLE;
    }
}

err_t jwtbundle_Bundle_print_fd(jwtbundle_Bundle *b, int offset, FILE *fd)
{
    BIO *out = BIO_new_fp(fd, BIO_NOCLOSE);
    if(!out) {
        return ERR_NEW_FP;
    }
    err_t error = jwtbundle_Bundle_print_BIO(b, offset, out);
    BIO_free(out);
    return error;
}

err_t jwtbundle_Bundle_print_stdout(jwtbundle_Bundle *b, int offset)
{
    return jwtbundle_Bundle_print_fd(b, offset, stdout);
}

err_t jwtbundle_Bundle_Print(jwtbundle_Bundle *b)
{
    // call print with default params.
    return jwtbundle_Bundle_print_stdout(b, 0);
}
