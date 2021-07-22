#include "c-spiffe/bundle/spiffebundle/bundle.h"
#include "c-spiffe/internal/jwtutil/util.h"
#include "c-spiffe/internal/pemutil/pem.h"
#include "c-spiffe/internal/x509util/util.h"
#include <check.h>

START_TEST(test_spiffebundle_New)
{
    spiffeid_TrustDomain td = { "example.com" };
    spiffebundle_Bundle *bundle = spiffebundle_New(td);

    ck_assert_ptr_ne(bundle, NULL);
    ck_assert_ptr_eq(bundle->x509_auths, NULL);
    ck_assert_ptr_ne(bundle->jwt_auths, NULL);
    ck_assert_uint_eq(shlenu(bundle->jwt_auths), 0);
    ck_assert_ptr_ne(bundle->td.name, NULL);
    ck_assert_str_eq(bundle->td.name, td.name);

    spiffebundle_Bundle_Free(bundle);
}
END_TEST

START_TEST(test_spiffebundle_Load)
{
    spiffeid_TrustDomain td = { "example.com" };
    err_t err;
    spiffebundle_Bundle *bundle
        = spiffebundle_Load(td, "./resources/jwks_valid_1.json", &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(bundle, NULL);
    ck_assert_ptr_ne(bundle->x509_auths, NULL);
    ck_assert_uint_eq(arrlenu(bundle->x509_auths), 1);
    ck_assert_ptr_ne(bundle->jwt_auths, NULL);
    ck_assert_uint_eq(shlenu(bundle->jwt_auths), 1);
    ck_assert_ptr_ne(bundle->td.name, NULL);
    ck_assert_str_eq(bundle->td.name, td.name);

    spiffebundle_Bundle_Free(bundle);
}
END_TEST

START_TEST(test_spiffebundle_Parse)
{
    FILE *f = fopen("./resources/jwks_valid_1.json", "r");

    ck_assert_ptr_ne(f, NULL);

    string_t str = FILE_to_string(f);
    fclose(f);
    spiffeid_TrustDomain td = { "example.com" };
    err_t err;
    spiffebundle_Bundle *bundle = spiffebundle_Parse(td, str, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(bundle, NULL);
    ck_assert_ptr_ne(bundle->x509_auths, NULL);
    ck_assert_uint_eq(arrlenu(bundle->x509_auths), 1);
    ck_assert_ptr_ne(bundle->jwt_auths, NULL);
    ck_assert_uint_eq(shlenu(bundle->jwt_auths), 1);
    ck_assert_ptr_ne(bundle->td.name, NULL);
    ck_assert_str_eq(bundle->td.name, td.name);

    arrfree(str);
    spiffebundle_Bundle_Free(bundle);
}
END_TEST

START_TEST(test_spiffebundle_FromX509Bundle)
{
    spiffeid_TrustDomain td = { "example.com" };
    err_t err;
    x509bundle_Bundle *x509bundle = x509bundle_Load(
        td, "./resources/good-leaf-and-intermediate.pem", &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(x509bundle, NULL);

    spiffebundle_Bundle *bundle = spiffebundle_FromX509Bundle(x509bundle);

    ck_assert_ptr_ne(bundle, NULL);
    ck_assert_ptr_ne(bundle->x509_auths, NULL);
    ck_assert_uint_eq(arrlenu(bundle->x509_auths), 2);
    ck_assert_ptr_ne(bundle->jwt_auths, NULL);
    ck_assert_uint_eq(shlenu(bundle->jwt_auths), 0);
    ck_assert_ptr_ne(bundle->td.name, NULL);
    ck_assert_str_eq(bundle->td.name, td.name);

    x509bundle_Bundle_Free(x509bundle);
    spiffebundle_Bundle_Free(bundle);
}
END_TEST

START_TEST(test_spiffebundle_FromJWTBundle)
{
    spiffeid_TrustDomain td = { "example.com" };
    err_t err;
    jwtbundle_Bundle *jwtbundle
        = jwtbundle_Load(td, "./resources/jwk_keys.json", &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(jwtbundle, NULL);

    spiffebundle_Bundle *bundle = spiffebundle_FromJWTBundle(jwtbundle);

    ck_assert_ptr_ne(bundle, NULL);
    ck_assert_ptr_eq(bundle->x509_auths, NULL);
    ck_assert_ptr_ne(bundle->jwt_auths, NULL);
    ck_assert_uint_eq(shlenu(bundle->jwt_auths), 3);
    ck_assert_ptr_ne(bundle->td.name, NULL);
    ck_assert_str_eq(bundle->td.name, td.name);

    jwtbundle_Bundle_Free(jwtbundle);
    spiffebundle_Bundle_Free(bundle);
}
END_TEST

START_TEST(test_spiffebundle_FromX509Authorities)
{
    FILE *f = fopen("./resources/good-leaf-and-intermediate.pem", "r");

    ck_assert_ptr_ne(f, NULL);

    byte *bytes = FILE_to_bytes(f);
    fclose(f);

    err_t err;
    X509 **certs = pemutil_ParseCertificates(bytes, &err);

    ck_assert_uint_eq(err, NO_ERROR);

    spiffeid_TrustDomain td = { "example.com" };
    spiffebundle_Bundle *bundle = spiffebundle_FromX509Authorities(td, certs);

    ck_assert_ptr_ne(bundle, NULL);
    ck_assert_ptr_ne(bundle->x509_auths, NULL);
    ck_assert_uint_eq(arrlenu(bundle->x509_auths), 2);
    ck_assert_ptr_ne(bundle->jwt_auths, NULL);
    ck_assert_uint_eq(shlenu(bundle->jwt_auths), 0);
    ck_assert_ptr_ne(bundle->td.name, NULL);
    ck_assert_str_eq(bundle->td.name, td.name);

    arrfree(bytes);
    for(size_t i = 0, size = arrlenu(certs); i < size; ++i) {
        X509_free(certs[i]);
    }
    arrfree(certs);
    spiffebundle_Bundle_Free(bundle);
}
END_TEST

START_TEST(test_spiffebundle_FromJWTAuthorities)
{
    FILE *f = fopen("./resources/jwk_keys.json", "r");

    ck_assert_ptr_ne(f, NULL);

    byte *bytes = FILE_to_bytes(f);
    fclose(f);

    err_t err;
    jwtutil_JWKS jwks = jwtutil_ParseJWKS(bytes, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_uint_eq(arrlenu(jwks.x509_auths), 0);
    ck_assert_ptr_ne(jwks.jwt_auths, NULL);

    spiffeid_TrustDomain td = { "example.com" };
    spiffebundle_Bundle *bundle
        = spiffebundle_FromJWTAuthorities(td, jwks.jwt_auths);

    ck_assert_ptr_ne(bundle, NULL);
    ck_assert_ptr_eq(bundle->x509_auths, NULL);
    ck_assert_ptr_ne(bundle->jwt_auths, NULL);
    ck_assert_uint_eq(shlenu(bundle->jwt_auths), 3);
    ck_assert_ptr_ne(bundle->td.name, NULL);
    ck_assert_str_eq(bundle->td.name, td.name);

    arrfree(bytes);
    jwtutil_JWKS_Free(&jwks);
    spiffebundle_Bundle_Free(bundle);
}
END_TEST

START_TEST(test_spiffebundle_Bundle_X509Authorities)
{
    spiffeid_TrustDomain td = { "example.com" };
    err_t err;
    spiffebundle_Bundle *bundle
        = spiffebundle_Load(td, "./resources/jwks_valid_1.json", &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(bundle, NULL);

    X509 **certs = spiffebundle_Bundle_X509Authorities(bundle);

    ck_assert(x509util_CertsEqual(bundle->x509_auths, certs));

    for(size_t i = 0, size = arrlenu(certs); i < size; ++i) {
        X509_free(certs[i]);
    }
    arrfree(certs);
    spiffebundle_Bundle_Free(bundle);
}
END_TEST

START_TEST(test_spiffebundle_Bundle_AddX509Authority)
{
    spiffeid_TrustDomain td = { "example.com" };
    spiffebundle_Bundle *bundle = spiffebundle_New(td);

    FILE *f = fopen("./resources/good-leaf-and-intermediate.pem", "r");
    X509 *leaf = PEM_read_X509(f, NULL, NULL, NULL);
    X509 *inter = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);

    ck_assert_ptr_ne(leaf, NULL);
    ck_assert_ptr_ne(inter, NULL);

    spiffebundle_Bundle_AddX509Authority(bundle, leaf);
    ck_assert_uint_eq(arrlenu(bundle->x509_auths), 1);
    ck_assert_int_eq(X509_cmp(bundle->x509_auths[0], leaf), 0);

    spiffebundle_Bundle_AddX509Authority(bundle, inter);
    ck_assert_uint_eq(arrlenu(bundle->x509_auths), 2);
    ck_assert_int_eq(X509_cmp(bundle->x509_auths[1], inter), 0);

    // can not add already present certificate
    spiffebundle_Bundle_AddX509Authority(bundle, leaf);
    ck_assert_uint_eq(arrlenu(bundle->x509_auths), 2);

    // can not add already present certificate
    spiffebundle_Bundle_AddX509Authority(bundle, inter);
    ck_assert_uint_eq(arrlenu(bundle->x509_auths), 2);

    spiffebundle_Bundle_Free(bundle);
    X509_free(leaf);
    X509_free(inter);
}
END_TEST

START_TEST(test_spiffebundle_Bundle_RemoveX509Authority)
{
    FILE *f = fopen("./resources/good-leaf-and-intermediate.pem", "r");

    ck_assert_ptr_ne(f, NULL);

    byte *bytes = FILE_to_bytes(f);
    fclose(f);

    err_t err;
    X509 **certs = pemutil_ParseCertificates(bytes, &err);

    ck_assert_uint_eq(err, NO_ERROR);

    spiffeid_TrustDomain td = { "example.com" };
    spiffebundle_Bundle *bundle = spiffebundle_FromX509Authorities(td, certs);

    ck_assert_ptr_ne(bundle, NULL);
    ck_assert_ptr_ne(bundle->x509_auths, NULL);
    ck_assert_uint_eq(arrlenu(bundle->x509_auths), 2);

    spiffebundle_Bundle_RemoveX509Authority(bundle, certs[1]);

    ck_assert_ptr_ne(bundle->x509_auths, NULL);
    ck_assert_uint_eq(arrlenu(bundle->x509_auths), 1);

    spiffebundle_Bundle_RemoveX509Authority(bundle, certs[0]);

    ck_assert_ptr_ne(bundle->x509_auths, NULL);
    ck_assert_uint_eq(arrlenu(bundle->x509_auths), 0);

    arrfree(bytes);
    for(size_t i = 0, size = arrlenu(certs); i < size; ++i) {
        X509_free(certs[i]);
    }
    arrfree(certs);
    spiffebundle_Bundle_Free(bundle);
}
END_TEST

START_TEST(test_spiffebundle_Bundle_HasX509Authority)
{
    FILE *f = fopen("./resources/good-leaf-and-intermediate.pem", "r");

    ck_assert_ptr_ne(f, NULL);

    byte *bytes = FILE_to_bytes(f);
    fclose(f);

    err_t err;
    X509 **certs = pemutil_ParseCertificates(bytes, &err);

    ck_assert_uint_eq(err, NO_ERROR);

    spiffeid_TrustDomain td = { "example.com" };
    spiffebundle_Bundle *bundle = spiffebundle_FromX509Authorities(td, certs);

    ck_assert_ptr_ne(bundle, NULL);
    ck_assert_ptr_ne(bundle->x509_auths, NULL);

    ck_assert(spiffebundle_Bundle_HasX509Authority(bundle, certs[0]));
    ck_assert(spiffebundle_Bundle_HasX509Authority(bundle, certs[1]));

    spiffebundle_Bundle_RemoveX509Authority(bundle, certs[0]);

    ck_assert(!spiffebundle_Bundle_HasX509Authority(bundle, certs[0]));
    ck_assert(spiffebundle_Bundle_HasX509Authority(bundle, certs[1]));

    spiffebundle_Bundle_RemoveX509Authority(bundle, certs[1]);

    ck_assert(!spiffebundle_Bundle_HasX509Authority(bundle, certs[0]));
    ck_assert(!spiffebundle_Bundle_HasX509Authority(bundle, certs[1]));

    arrfree(bytes);
    for(size_t i = 0, size = arrlenu(certs); i < size; ++i) {
        X509_free(certs[i]);
    }
    arrfree(certs);
    spiffebundle_Bundle_Free(bundle);
}
END_TEST

START_TEST(test_spiffebundle_Bundle_SetX509Authorities)
{
    spiffeid_TrustDomain td = { "example.com" };
    err_t err;
    spiffebundle_Bundle *bundle
        = spiffebundle_Load(td, "./resources/jwks_valid_1.json", &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(bundle, NULL);

    FILE *f = fopen("./resources/good-leaf-and-intermediate.pem", "r");

    ck_assert_ptr_ne(f, NULL);

    byte *bytes = FILE_to_bytes(f);
    fclose(f);

    X509 **certs = pemutil_ParseCertificates(bytes, &err);

    ck_assert_uint_eq(err, NO_ERROR);

    spiffebundle_Bundle_SetX509Authorities(bundle, certs);

    ck_assert_ptr_ne(bundle->x509_auths, NULL);
    ck_assert_uint_eq(arrlenu(bundle->x509_auths), 2);
    ck_assert_int_eq(X509_cmp(bundle->x509_auths[0], certs[0]), 0);
    ck_assert_int_eq(X509_cmp(bundle->x509_auths[1], certs[1]), 0);

    spiffebundle_Bundle_Free(bundle);
    arrfree(bytes);
    for(size_t i = 0, size = arrlenu(certs); i < size; ++i) {
        X509_free(certs[i]);
    }
    arrfree(certs);
}
END_TEST

START_TEST(test_spiffebundle_Bundle_JWTAuthorities)
{
    spiffeid_TrustDomain td = { "example.com" };
    err_t err;
    spiffebundle_Bundle *bundle
        = spiffebundle_Load(td, "./resources/jwks_valid_1.json", &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(bundle, NULL);

    map_string_EVP_PKEY *keys = spiffebundle_Bundle_JWTAuthorities(bundle);

    ck_assert(jwtutil_JWTAuthoritiesEqual(bundle->jwt_auths, keys));

    spiffebundle_Bundle_Free(bundle);
    for(size_t i = 0, size = shlenu(keys); i < size; ++i) {
        EVP_PKEY_free(keys[i].value);
    }
    shfree(keys);
}
END_TEST

START_TEST(test_spiffebundle_Bundle_FindJWTAuthority)
{
    spiffeid_TrustDomain td = { "example.com" };
    err_t err;
    spiffebundle_Bundle *bundle
        = spiffebundle_Load(td, "./resources/jwks_valid_2.json", &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(bundle, NULL);

    bool suc;
    EVP_PKEY *key = spiffebundle_Bundle_FindJWTAuthority(
        bundle, "IRsID4VIM3T11TsK43Ny1DgCD5UNWhva", &suc);
    ck_assert_ptr_ne(key, NULL);
    ck_assert(suc);

    key = spiffebundle_Bundle_FindJWTAuthority(
        bundle, "IRsID4VIM3T11TsK43Ny1DgCD5UNWhva", &suc);
    ck_assert_ptr_ne(key, NULL);
    ck_assert(suc);

    key = spiffebundle_Bundle_FindJWTAuthority(
        bundle, "qjwWkiMpkHzIxsSrAsLxSZ2WZ8AyMESx", &suc);
    ck_assert_ptr_ne(key, NULL);
    ck_assert(suc);

    key = spiffebundle_Bundle_FindJWTAuthority(
        bundle, "uNhqAaPI7NDn7IHOsa2ac1BF4O5qGxjZ", &suc);
    ck_assert_ptr_ne(key, NULL);
    ck_assert(suc);

    key = spiffebundle_Bundle_FindJWTAuthority(
        bundle, "y3UHKFp0WqPpG7gVr3FKieiEzwH8fTMm", &suc);
    ck_assert_ptr_ne(key, NULL);
    ck_assert(suc);

    key = spiffebundle_Bundle_FindJWTAuthority(
        bundle, "mbrcuIaIUUapdCCmhQon4xJSicDmAVfK", &suc);
    ck_assert_ptr_ne(key, NULL);
    ck_assert(suc);

    key = spiffebundle_Bundle_FindJWTAuthority(
        bundle, "cHPeHMMEtvTeSMBc20DzPPhkF41BN2WJ", &suc);
    ck_assert_ptr_ne(key, NULL);
    ck_assert(suc);

    key = spiffebundle_Bundle_FindJWTAuthority(
        bundle, "C6vs25welZOx6WksNYfbMfiw9l96pMnD", &suc);
    ck_assert_ptr_eq(key, NULL);
    ck_assert(!suc);

    spiffebundle_Bundle_Free(bundle);
}
END_TEST

START_TEST(test_spiffebundle_Bundle_HasJWTAuthority)
{
    spiffeid_TrustDomain td = { "example.com" };
    err_t err;
    spiffebundle_Bundle *bundle
        = spiffebundle_Load(td, "./resources/jwks_valid_2.json", &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(bundle, NULL);

    bool suc = spiffebundle_Bundle_HasJWTAuthority(
        bundle, "IRsID4VIM3T11TsK43Ny1DgCD5UNWhva");
    ck_assert(suc);

    suc = spiffebundle_Bundle_HasJWTAuthority(
        bundle, "IRsID4VIM3T11TsK43Ny1DgCD5UNWhva");
    ck_assert(suc);

    suc = spiffebundle_Bundle_HasJWTAuthority(
        bundle, "qjwWkiMpkHzIxsSrAsLxSZ2WZ8AyMESx");
    ck_assert(suc);

    suc = spiffebundle_Bundle_HasJWTAuthority(
        bundle, "uNhqAaPI7NDn7IHOsa2ac1BF4O5qGxjZ");
    ck_assert(suc);

    suc = spiffebundle_Bundle_HasJWTAuthority(
        bundle, "y3UHKFp0WqPpG7gVr3FKieiEzwH8fTMm");
    ck_assert(suc);

    suc = spiffebundle_Bundle_HasJWTAuthority(
        bundle, "mbrcuIaIUUapdCCmhQon4xJSicDmAVfK");
    ck_assert(suc);

    suc = spiffebundle_Bundle_HasJWTAuthority(
        bundle, "cHPeHMMEtvTeSMBc20DzPPhkF41BN2WJ");
    ck_assert(suc);

    suc = spiffebundle_Bundle_HasJWTAuthority(
        bundle, "C6vs25welZOx6WksNYfbMfiw9l96pMnD");
    ck_assert(!suc);

    spiffebundle_Bundle_Free(bundle);
}
END_TEST

START_TEST(test_spiffebundle_Bundle_AddJWTAuthority)
{
    spiffeid_TrustDomain td = { "example.com" };
    spiffebundle_Bundle *bundle = spiffebundle_New(td);

    FILE *f = fopen("./resources/jwk_keys.json", "r");

    ck_assert_ptr_ne(f, NULL);

    string_t str = FILE_to_string(f);
    fclose(f);

    err_t err;
    jwtutil_JWKS keys = jwtutil_ParseJWKS(str, &err);

    ck_assert_uint_eq(err, NO_ERROR);

    const char *key_str0 = "ff3c5c96-392e-46ef-a839-6ff16027af78";
    const char *key_str1 = "79c809dd1186cc228c4baf9358599530ce92b4c8";

    EVP_PKEY *key0 = shget(keys.jwt_auths, key_str0);
    EVP_PKEY *key1 = shget(keys.jwt_auths, key_str1);

    spiffebundle_Bundle_AddJWTAuthority(bundle, key_str0, key0);
    ck_assert_uint_eq(shlenu(bundle->jwt_auths), 1);
    ck_assert(spiffebundle_Bundle_HasJWTAuthority(bundle, key_str0));

    spiffebundle_Bundle_AddJWTAuthority(bundle, key_str1, key1);
    ck_assert_uint_eq(shlenu(bundle->jwt_auths), 2);
    ck_assert(spiffebundle_Bundle_HasJWTAuthority(bundle, key_str1));

    spiffebundle_Bundle_Free(bundle);
    arrfree(str);
    jwtutil_JWKS_Free(&keys);
}
END_TEST

START_TEST(test_spiffebundle_Bundle_RemoveJWTAuthority)
{
    spiffeid_TrustDomain td = { "example.com" };
    spiffebundle_Bundle *bundle = spiffebundle_New(td);

    FILE *f = fopen("./resources/jwk_keys.json", "r");

    ck_assert_ptr_ne(f, NULL);

    string_t str = FILE_to_string(f);
    fclose(f);

    err_t err;
    jwtutil_JWKS keys = jwtutil_ParseJWKS(str, &err);

    ck_assert_uint_eq(err, NO_ERROR);

    const char *key_str0 = "ff3c5c96-392e-46ef-a839-6ff16027af78";
    const char *key_str1 = "79c809dd1186cc228c4baf9358599530ce92b4c8";

    EVP_PKEY *key0 = shget(keys.jwt_auths, key_str0);
    EVP_PKEY *key1 = shget(keys.jwt_auths, key_str1);

    spiffebundle_Bundle_AddJWTAuthority(bundle, key_str0, key0);
    spiffebundle_Bundle_AddJWTAuthority(bundle, key_str1, key1);

    ck_assert_uint_eq(shlenu(bundle->jwt_auths), 2);

    spiffebundle_Bundle_RemoveJWTAuthority(bundle, key_str0);
    ck_assert_uint_eq(shlenu(bundle->jwt_auths), 1);
    ck_assert(!spiffebundle_Bundle_HasJWTAuthority(bundle, key_str0));
    ck_assert(spiffebundle_Bundle_HasJWTAuthority(bundle, key_str1));

    spiffebundle_Bundle_RemoveJWTAuthority(bundle, key_str1);
    ck_assert_uint_eq(shlenu(bundle->jwt_auths), 0);
    ck_assert(!spiffebundle_Bundle_HasJWTAuthority(bundle, key_str0));
    ck_assert(!spiffebundle_Bundle_HasJWTAuthority(bundle, key_str1));

    spiffebundle_Bundle_Free(bundle);
    arrfree(str);
    jwtutil_JWKS_Free(&keys);
}
END_TEST

START_TEST(test_spiffebundle_Bundle_SetJWTAuthorities)
{
    spiffeid_TrustDomain td = { "example.com" };
    err_t err;
    spiffebundle_Bundle *bundle
        = spiffebundle_Load(td, "./resources/jwks_valid_2.json", &err);

    ck_assert_uint_eq(err, NO_ERROR);

    FILE *f = fopen("./resources/jwk_keys.json", "r");

    ck_assert_ptr_ne(f, NULL);

    string_t str = FILE_to_string(f);
    fclose(f);

    jwtutil_JWKS keys = jwtutil_ParseJWKS(str, &err);

    ck_assert_uint_eq(err, NO_ERROR);

    spiffebundle_Bundle_SetJWTAuthorities(bundle, keys.jwt_auths);

    ck_assert(jwtutil_JWTAuthoritiesEqual(bundle->jwt_auths, keys.jwt_auths));

    spiffebundle_Bundle_Free(bundle);
    arrfree(str);
    jwtutil_JWKS_Free(&keys);
}
END_TEST

START_TEST(test_spiffebundle_Bundle_Empty)
{
    spiffeid_TrustDomain td = { "example.com" };
    spiffebundle_Bundle *bundle = spiffebundle_New(td);

    ck_assert(spiffebundle_Bundle_Empty(bundle));

    spiffebundle_Bundle_Free(bundle);
}
END_TEST

START_TEST(test_spiffebundle_Bundle_RefreshHint)
{
    spiffeid_TrustDomain td = { "example.com" };
    spiffebundle_Bundle *bundle = spiffebundle_New(td);

    bool suc;
    struct timespec ts = spiffebundle_Bundle_RefreshHint(bundle, &suc);

    ck_assert(!suc);
    ck_assert_int_lt(bundle->refresh_hint.tv_sec, 0);

    ts.tv_sec = 10;
    ts.tv_nsec = 100;
    spiffebundle_Bundle_SetRefreshHint(bundle, &ts);
    ts = spiffebundle_Bundle_RefreshHint(bundle, &suc);

    ck_assert(suc);
    ck_assert_int_eq(bundle->refresh_hint.tv_sec, ts.tv_sec);
    ck_assert_int_eq(bundle->refresh_hint.tv_nsec, ts.tv_nsec);

    spiffebundle_Bundle_Free(bundle);
}
END_TEST

START_TEST(test_spiffebundle_Bundle_ClearRefreshHint)
{
    spiffeid_TrustDomain td = { "example.com" };
    spiffebundle_Bundle *bundle = spiffebundle_New(td);

    struct timespec ts = { .tv_sec = 10, .tv_nsec = 100 };

    spiffebundle_Bundle_SetRefreshHint(bundle, &ts);
    spiffebundle_Bundle_ClearRefreshHint(bundle);

    ck_assert_int_lt(bundle->refresh_hint.tv_sec, 0);
    ck_assert_int_eq(bundle->refresh_hint.tv_nsec, 0);

    spiffebundle_Bundle_Free(bundle);
}
END_TEST

START_TEST(test_spiffebundle_Bundle_Marshal)
{
    spiffeid_TrustDomain td = { "example.com" };
    err_t err;
    spiffebundle_Bundle *bundle
        = spiffebundle_Load(td, "./resources/jwks_valid_2.json", &err);

    string_t str = spiffebundle_Bundle_Marshal(bundle, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(str, NULL);

    spiffebundle_Bundle_Free(bundle);
    arrfree(str);
    str = spiffebundle_Bundle_Marshal(NULL, &err);

    ck_assert_uint_eq(err, ERR_NULL_BUNDLE);
    ck_assert_ptr_eq(str, NULL);
}
END_TEST

START_TEST(test_spiffebundle_Bundle_SequenceNumber)
{
    spiffeid_TrustDomain td = { "example.com" };
    spiffebundle_Bundle *bundle = spiffebundle_New(td);

    bool suc;
    int64_t sn = spiffebundle_Bundle_SequenceNumber(bundle, &suc);

    ck_assert(!suc);
    ck_assert_int_lt(sn, 0);

    spiffebundle_Bundle_SetSequenceNumber(bundle, 1000);
    sn = spiffebundle_Bundle_SequenceNumber(bundle, &suc);

    ck_assert(suc);
    ck_assert_int_eq(sn, 1000);

    spiffebundle_Bundle_Free(bundle);
}
END_TEST

START_TEST(test_spiffebundle_Bundle_ClearSequenceNumber)
{
    spiffeid_TrustDomain td = { "example.com" };
    spiffebundle_Bundle *bundle = spiffebundle_New(td);

    spiffebundle_Bundle_SetSequenceNumber(bundle, 1000);
    spiffebundle_Bundle_ClearSequenceNumber(bundle);
    bool suc;
    int64_t sn = spiffebundle_Bundle_SequenceNumber(bundle, &suc);

    ck_assert(!suc);
    ck_assert_int_lt(sn, 0);

    spiffebundle_Bundle_Free(bundle);
}
END_TEST

START_TEST(test_spiffebundle_Bundle_Clone)
{
    spiffeid_TrustDomain td = { "example.com" };
    err_t err;
    spiffebundle_Bundle *bundle
        = spiffebundle_Load(td, "./resources/jwks_valid_1.json", &err);
    spiffebundle_Bundle *copy_bundle = spiffebundle_Bundle_Clone(bundle);

    ck_assert_ptr_ne(copy_bundle, NULL);
    ck_assert_ptr_ne(copy_bundle->td.name, NULL);
    ck_assert_str_eq(copy_bundle->td.name, bundle->td.name);
    ck_assert(
        x509util_CertsEqual(copy_bundle->x509_auths, bundle->x509_auths));
    ck_assert(jwtutil_JWTAuthoritiesEqual(copy_bundle->jwt_auths,
                                          bundle->jwt_auths));
    ck_assert_int_eq(copy_bundle->refresh_hint.tv_sec,
                     bundle->refresh_hint.tv_sec);
    ck_assert_int_eq(copy_bundle->refresh_hint.tv_nsec,
                     bundle->refresh_hint.tv_nsec);
    ck_assert_int_eq(copy_bundle->seq_number, bundle->seq_number);

    spiffebundle_Bundle_Free(bundle);
    spiffebundle_Bundle_Free(copy_bundle);
}
END_TEST

START_TEST(test_spiffebundle_Bundle_X509Bundle)
{
    spiffeid_TrustDomain td = { "example.com" };
    err_t err;
    spiffebundle_Bundle *bundle
        = spiffebundle_Load(td, "./resources/jwks_valid_1.json", &err);
    x509bundle_Bundle *x509bundle = spiffebundle_Bundle_X509Bundle(bundle);

    ck_assert_ptr_ne(x509bundle, NULL);
    ck_assert_ptr_ne(x509bundle->td.name, NULL);
    ck_assert_str_eq(x509bundle->td.name, bundle->td.name);
    ck_assert(x509util_CertsEqual(x509bundle->auths, bundle->x509_auths));

    spiffebundle_Bundle_Free(bundle);
    x509bundle_Bundle_Free(x509bundle);
}
END_TEST

START_TEST(test_spiffebundle_Bundle_JWTBundle)
{
    spiffeid_TrustDomain td = { "example.com" };
    err_t err;
    spiffebundle_Bundle *bundle
        = spiffebundle_Load(td, "./resources/jwks_valid_1.json", &err);
    jwtbundle_Bundle *jwtbundle = spiffebundle_Bundle_JWTBundle(bundle);

    ck_assert_ptr_ne(jwtbundle, NULL);
    ck_assert_ptr_ne(jwtbundle->td.name, NULL);
    ck_assert_str_eq(jwtbundle->td.name, bundle->td.name);
    ck_assert(
        jwtutil_JWTAuthoritiesEqual(jwtbundle->auths, bundle->jwt_auths));

    spiffebundle_Bundle_Free(bundle);
    jwtbundle_Bundle_Free(jwtbundle);
}
END_TEST

START_TEST(test_spiffebundle_Bundle_GetBundleForTrustDomain)
{
    spiffeid_TrustDomain td = { "example.com" };
    err_t err;
    spiffebundle_Bundle *bundle
        = spiffebundle_Load(td, "./resources/jwks_valid_1.json", &err);

    spiffebundle_Bundle *other_bundle
        = spiffebundle_Bundle_GetBundleForTrustDomain(bundle, td, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_eq(other_bundle, bundle);

    other_bundle = spiffebundle_Bundle_GetBundleForTrustDomain(
        bundle, (spiffeid_TrustDomain){ "example.org" }, &err);

    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert_ptr_ne(other_bundle, bundle);

    spiffebundle_Bundle_Free(bundle);
}
END_TEST

START_TEST(test_spiffebundle_Bundle_GetX509BundleForTrustDomain)
{
    spiffeid_TrustDomain td = { "example.com" };
    err_t err;
    spiffebundle_Bundle *bundle
        = spiffebundle_Load(td, "./resources/jwks_valid_1.json", &err);
    x509bundle_Bundle *x509bundle
        = spiffebundle_Bundle_GetX509BundleForTrustDomain(bundle, td, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(x509bundle, NULL);
    ck_assert(x509util_CertsEqual(x509bundle->auths, bundle->x509_auths));

    spiffebundle_Bundle_Free(bundle);
    x509bundle_Bundle_Free(x509bundle);
}
END_TEST

START_TEST(test_spiffebundle_Bundle_GetJWTBundleForTrustDomain)
{
    spiffeid_TrustDomain td = { "example.com" };
    err_t err;
    spiffebundle_Bundle *bundle
        = spiffebundle_Load(td, "./resources/jwks_valid_1.json", &err);
    jwtbundle_Bundle *jwtbundle
        = spiffebundle_Bundle_GetJWTBundleForTrustDomain(bundle, td, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(jwtbundle, NULL);
    ck_assert(
        jwtutil_JWTAuthoritiesEqual(jwtbundle->auths, bundle->jwt_auths));

    spiffebundle_Bundle_Free(bundle);
    jwtbundle_Bundle_Free(jwtbundle);
}
END_TEST

START_TEST(test_spiffebundle_Bundle_Equal)
{
    spiffeid_TrustDomain td = { "example.com" };
    err_t err;
    spiffebundle_Bundle *bundle
        = spiffebundle_Load(td, "./resources/jwks_valid_1.json", &err);
    spiffebundle_Bundle *copy_bundle = spiffebundle_Bundle_Clone(bundle);

    ck_assert(spiffebundle_Bundle_Equal(bundle, copy_bundle));

    spiffebundle_Bundle_RemoveJWTAuthority(bundle,
                                           "C6vs25welZOx6WksNYfbMfiw9l96pMnD");

    ck_assert(!spiffebundle_Bundle_Equal(bundle, copy_bundle));

    spiffebundle_Bundle_Free(bundle);
    spiffebundle_Bundle_Free(copy_bundle);
}
END_TEST

START_TEST(test_spiffebundle_Bundle_TrustDomain)
{
    spiffeid_TrustDomain td = { "example.com" };
    err_t err;
    spiffebundle_Bundle *bundle
        = spiffebundle_Load(td, "./resources/jwks_valid_1.json", &err);
    td = spiffebundle_Bundle_TrustDomain(bundle);

    ck_assert_ptr_ne(td.name, NULL);
    ck_assert_str_eq(td.name, bundle->td.name);

    spiffebundle_Bundle_Free(bundle);
}
END_TEST

Suite *bundle_suite(void)
{
    Suite *s = suite_create("bundle");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_spiffebundle_New);
    tcase_add_test(tc_core, test_spiffebundle_Load);
    tcase_add_test(tc_core, test_spiffebundle_Parse);
    tcase_add_test(tc_core, test_spiffebundle_FromX509Bundle);
    tcase_add_test(tc_core, test_spiffebundle_FromJWTBundle);
    tcase_add_test(tc_core, test_spiffebundle_FromX509Authorities);
    tcase_add_test(tc_core, test_spiffebundle_FromJWTAuthorities);
    tcase_add_test(tc_core, test_spiffebundle_Bundle_X509Authorities);
    tcase_add_test(tc_core, test_spiffebundle_Bundle_AddX509Authority);
    tcase_add_test(tc_core, test_spiffebundle_Bundle_RemoveX509Authority);
    tcase_add_test(tc_core, test_spiffebundle_Bundle_HasX509Authority);
    tcase_add_test(tc_core, test_spiffebundle_Bundle_SetX509Authorities);
    tcase_add_test(tc_core, test_spiffebundle_Bundle_JWTAuthorities);
    tcase_add_test(tc_core, test_spiffebundle_Bundle_FindJWTAuthority);
    tcase_add_test(tc_core, test_spiffebundle_Bundle_HasJWTAuthority);
    tcase_add_test(tc_core, test_spiffebundle_Bundle_AddJWTAuthority);
    tcase_add_test(tc_core, test_spiffebundle_Bundle_RemoveJWTAuthority);
    tcase_add_test(tc_core, test_spiffebundle_Bundle_SetJWTAuthorities);
    tcase_add_test(tc_core, test_spiffebundle_Bundle_Empty);
    tcase_add_test(tc_core, test_spiffebundle_Bundle_RefreshHint);
    tcase_add_test(tc_core, test_spiffebundle_Bundle_ClearRefreshHint);
    tcase_add_test(tc_core, test_spiffebundle_Bundle_Marshal);
    tcase_add_test(tc_core, test_spiffebundle_Bundle_SequenceNumber);
    tcase_add_test(tc_core, test_spiffebundle_Bundle_ClearSequenceNumber);
    tcase_add_test(tc_core, test_spiffebundle_Bundle_Clone);
    tcase_add_test(tc_core, test_spiffebundle_Bundle_X509Bundle);
    tcase_add_test(tc_core, test_spiffebundle_Bundle_JWTBundle);
    tcase_add_test(tc_core, test_spiffebundle_Bundle_GetBundleForTrustDomain);
    tcase_add_test(tc_core,
                   test_spiffebundle_Bundle_GetX509BundleForTrustDomain);
    tcase_add_test(tc_core,
                   test_spiffebundle_Bundle_GetJWTBundleForTrustDomain);
    tcase_add_test(tc_core, test_spiffebundle_Bundle_Equal);
    tcase_add_test(tc_core, test_spiffebundle_Bundle_TrustDomain);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    Suite *s = bundle_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
