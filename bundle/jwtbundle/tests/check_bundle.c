#include <openssl/pem.h>
#include <check.h>
#include "../src/bundle.h"
#include "../../../internal/jwtutil/src/util.h"
#include "../../../internal/cryptoutil/src/keys.h"
#include "../../../spiffeid/src/trustdomain.h"

START_TEST(test_jwtbundle_New)
{
    spiffeid_TrustDomain td = {"example.com"};
    jwtbundle_Bundle *bundle_ptr = jwtbundle_New(td);
    
    ck_assert(bundle_ptr->auths == NULL);
    ck_assert(!strcmp(bundle_ptr->td.name, "example.com"));

    jwtbundle_Bundle_Free(bundle_ptr, true);
}
END_TEST

START_TEST(test_jwtbundle_Parse)
{
    spiffeid_TrustDomain td = {"example.com"};
    err_t err;

    FILE *f = fopen("jwk_keys.json", "r");
    string_t buffer = FILE_to_string(f);
    fclose(f);

    jwtbundle_Bundle *bundle_ptr = jwtbundle_Parse(td, buffer, &err);
    arrfree(buffer);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_uint_eq(shlenu(bundle_ptr->auths), 3);
    for(size_t i = 0, size = shlenu(bundle_ptr->auths); i < size; ++i)
    {
        const EVP_PKEY *pkey = bundle_ptr->auths[i].value;
        ck_assert(pkey != NULL);
        const int key_type = EVP_PKEY_base_id(pkey);
        ck_assert(key_type == EVP_PKEY_RSA || key_type == EVP_PKEY_EC);
    }
    ck_assert(!strcmp(bundle_ptr->td.name, "example.com"));

    jwtbundle_Bundle_Free(bundle_ptr, true);
}
END_TEST

START_TEST(test_jwtbundle_Load)
{
    spiffeid_TrustDomain td = {"example.com"};
    err_t err;

    jwtbundle_Bundle *bundle_ptr = jwtbundle_Load(td, "jwk_keys.json", &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_uint_eq(shlenu(bundle_ptr->auths), 3);
    for(size_t i = 0, size = shlenu(bundle_ptr->auths); i < size; ++i)
    {
        const EVP_PKEY *pkey = bundle_ptr->auths[i].value;
        ck_assert(pkey != NULL);
        const int key_type = EVP_PKEY_base_id(pkey);
        ck_assert(key_type == EVP_PKEY_RSA || key_type == EVP_PKEY_EC);
    }
    ck_assert(!strcmp(bundle_ptr->td.name, "example.com"));

    jwtbundle_Bundle_Free(bundle_ptr, true);
}
END_TEST

START_TEST(test_jwtbundle_FromJWTAuthorities)
{
    const int ITERS = 6;
    const char *keys[] = {
        "key0",
        "key1",
        "key2",
        "key3",
        "key4",
        "key5"
    };

    const char *pubkeys[] = {
        "-----BEGIN PUBLIC KEY-----\n"
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRFNU++93aEvz3cV8LSUP9ib3i\n"
        "UxT7SufdVXcgVFK9M3BYzvroA1uO/parFOJABTkNhTPPP/6mjrU2CPEZJ1zIkpaS\n"
        "NJrrhpp/rNMO9nyLYPGs9MfdBiWUPmHW5mY1oD0ye4my0tEsHOlgHC8AhA8OtiHr\n"
        "6IY0agXmH/y5YmSWbwIDAQAB\n"
        "-----END PUBLIC KEY-----", 
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA61BjmfXGEvWmegnBGSuS\n"
        "+rU9soUg2FnODva32D1AqhwdziwHINFaD1MVlcrYG6XRKfkcxnaXGfFDWHLEvNBS\n"
        "EVCgJjtHAGZIm5GL/KA86KDp/CwDFMSwluowcXwDwoyinmeOY9eKyh6aY72xJh7n\n"
        "oLBBq1N0bWi1e2i+83txOCg4yV2oVXhBo8pYEJ8LT3el6Smxol3C1oFMVdwPgc0v\n"
        "Tl25XucMcG/ALE/KNY6pqC2AQ6R2ERlVgPiUWOPatVkt7+Bs3h5Ramxh7XjBOXeu\n"
        "lmCpGSynXNcpZ/06+vofGi/2MlpQZNhHAo8eayMp6FcvNucIpUndo1X8dKMv3Y26\n"
        "ZQIDAQAB\n"
        "-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn/8y3uYCQxSXZ58OYceG\n"
        "A4uPdGHZXDYOQR11xcHTrH13jJEzdkYZG8irtyG+m3Jb6f9F8WkmTZxl+4YtkJdN\n"
        "9WyrKhxq4Vbt42BthadX3Ty/pKkJ81Qn8KjxWoL+SMaCGFzRlfWsFju9Q5C7+aTj\n"
        "eEKyFujH5bUTGX87nULRfg67tmtxBlT8WWWtFe2O/wedBTGGQxXMpwh4ObjLl3Qh\n"
        "bfwxlBbh2N4471TyrErv04lbNecGaQqYxGrY8Ot3l2V2fXCzghAQg26Hc4dR2wyA\n"
        "PPgWq78db+gU3QsePeo2Ki5sonkcyQQQlCkL35Asbv8khvk90gist4kijPnVBCuv\n"
        "cwIDAQAB\n"
        "-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\n"
        "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBhsFCcWY2GaiN1BjPEd1v+ESKO6/0\n"
        "D0sUR4y1amHnOr3FZx6TdqdoSBqxownQrnAKGCwagGxUb7BWwPFgHqKQJHgBq+J7\n"
        "F+6m5SKAEL1wS5pqya91N7oudF3yFW8oZRE4RQRdSLl3fV2aVXKwGDXciwhUhw8k\n"
        "x5OS4iZpMAY+LI4WVGU=\n"
        "-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\n"
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOr6rMmRRNKuZuwws/hWwFTM6ECEE\n"
        "aJGGARCJUO4UfoURl8b4JThGt8VDFKeR2i+ZxE+xh/wTBaJ/zvtSqZiNnQ==\n"
        "-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\n"
        "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEAs5xEIm001FFsRpXSRFEy57+swcr3nW9\n"
        "SP3ERlrT539LE/x2auTwUVTCkaFS6R5IBl2QIvEml+UXgBU0sDK3PqZsqHcQzvBz\n"
        "Z/lX7NehqphbVCQBr3nkhDwyq0tkrmyD\n"
        "-----END PUBLIC KEY-----"
    };

    BIO *bio_mems[] = {
        BIO_new_mem_buf((void*) pubkeys[0], -1),
        BIO_new_mem_buf((void*) pubkeys[1], -1),
        BIO_new_mem_buf((void*) pubkeys[2], -1),
        BIO_new_mem_buf((void*) pubkeys[3], -1),
        BIO_new_mem_buf((void*) pubkeys[4], -1),
        BIO_new_mem_buf((void*) pubkeys[5], -1)
    };

    EVP_PKEY *evp_pubkeys[] = {
        PEM_read_bio_PUBKEY(bio_mems[0], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[1], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[2], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[3], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[4], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[5], NULL, NULL, NULL)
    };

    map_string_EVP_PKEY *jwt_auths = NULL;

    for(int i = 0; i < ITERS; ++i)
    {
        shput(jwt_auths, keys[i], evp_pubkeys[i]);
    }

    spiffeid_TrustDomain td = {"example.com"};
    jwtbundle_Bundle *bundle_ptr = jwtbundle_FromJWTAuthorities(td, jwt_auths);

    ck_assert(jwtutil_JWTAuthoritiesEqual(jwt_auths, bundle_ptr->auths));
    ck_assert(!strcmp(bundle_ptr->td.name, "example.com"));

    for(int i = 0; i < ITERS; ++i)
    {
        BIO_free(bio_mems[i]);
        EVP_PKEY_free(evp_pubkeys[i]);
    }
    jwtbundle_Bundle_Free(bundle_ptr, true);
}
END_TEST

START_TEST(test_jwtbundle_Bundle_JWTAuthorities)
{
    spiffeid_TrustDomain td = {"example.com"};
    err_t err;

    jwtbundle_Bundle *bundle_ptr = jwtbundle_Load(td, "jwk_keys.json", &err);
    map_string_EVP_PKEY *jwt_auths = jwtbundle_Bundle_JWTAuthorities(bundle_ptr);

    ck_assert(jwtutil_JWTAuthoritiesEqual(jwt_auths, bundle_ptr->auths));

    jwtbundle_Bundle_Free(bundle_ptr, true);
    for(size_t i = 0, size = shlenu(jwt_auths); i < size; ++i)
    {
        EVP_PKEY_free(jwt_auths[i].value);
    }
    shfree(jwt_auths);
}
END_TEST

START_TEST(test_jwtbundle_Bundle_FindJWTAuthority)
{
    const int ITERS = 6;
    const char *keys[] = {
        "key0",
        "key1",
        "key2",
        "key3",
        "key4",
        "key5"
    };

    const char *pubkeys[] = {
        "-----BEGIN PUBLIC KEY-----\n"
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRFNU++93aEvz3cV8LSUP9ib3i\n"
        "UxT7SufdVXcgVFK9M3BYzvroA1uO/parFOJABTkNhTPPP/6mjrU2CPEZJ1zIkpaS\n"
        "NJrrhpp/rNMO9nyLYPGs9MfdBiWUPmHW5mY1oD0ye4my0tEsHOlgHC8AhA8OtiHr\n"
        "6IY0agXmH/y5YmSWbwIDAQAB\n"
        "-----END PUBLIC KEY-----", 
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA61BjmfXGEvWmegnBGSuS\n"
        "+rU9soUg2FnODva32D1AqhwdziwHINFaD1MVlcrYG6XRKfkcxnaXGfFDWHLEvNBS\n"
        "EVCgJjtHAGZIm5GL/KA86KDp/CwDFMSwluowcXwDwoyinmeOY9eKyh6aY72xJh7n\n"
        "oLBBq1N0bWi1e2i+83txOCg4yV2oVXhBo8pYEJ8LT3el6Smxol3C1oFMVdwPgc0v\n"
        "Tl25XucMcG/ALE/KNY6pqC2AQ6R2ERlVgPiUWOPatVkt7+Bs3h5Ramxh7XjBOXeu\n"
        "lmCpGSynXNcpZ/06+vofGi/2MlpQZNhHAo8eayMp6FcvNucIpUndo1X8dKMv3Y26\n"
        "ZQIDAQAB\n"
        "-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn/8y3uYCQxSXZ58OYceG\n"
        "A4uPdGHZXDYOQR11xcHTrH13jJEzdkYZG8irtyG+m3Jb6f9F8WkmTZxl+4YtkJdN\n"
        "9WyrKhxq4Vbt42BthadX3Ty/pKkJ81Qn8KjxWoL+SMaCGFzRlfWsFju9Q5C7+aTj\n"
        "eEKyFujH5bUTGX87nULRfg67tmtxBlT8WWWtFe2O/wedBTGGQxXMpwh4ObjLl3Qh\n"
        "bfwxlBbh2N4471TyrErv04lbNecGaQqYxGrY8Ot3l2V2fXCzghAQg26Hc4dR2wyA\n"
        "PPgWq78db+gU3QsePeo2Ki5sonkcyQQQlCkL35Asbv8khvk90gist4kijPnVBCuv\n"
        "cwIDAQAB\n"
        "-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\n"
        "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBhsFCcWY2GaiN1BjPEd1v+ESKO6/0\n"
        "D0sUR4y1amHnOr3FZx6TdqdoSBqxownQrnAKGCwagGxUb7BWwPFgHqKQJHgBq+J7\n"
        "F+6m5SKAEL1wS5pqya91N7oudF3yFW8oZRE4RQRdSLl3fV2aVXKwGDXciwhUhw8k\n"
        "x5OS4iZpMAY+LI4WVGU=\n"
        "-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\n"
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOr6rMmRRNKuZuwws/hWwFTM6ECEE\n"
        "aJGGARCJUO4UfoURl8b4JThGt8VDFKeR2i+ZxE+xh/wTBaJ/zvtSqZiNnQ==\n"
        "-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\n"
        "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEAs5xEIm001FFsRpXSRFEy57+swcr3nW9\n"
        "SP3ERlrT539LE/x2auTwUVTCkaFS6R5IBl2QIvEml+UXgBU0sDK3PqZsqHcQzvBz\n"
        "Z/lX7NehqphbVCQBr3nkhDwyq0tkrmyD\n"
        "-----END PUBLIC KEY-----"
    };

    BIO *bio_mems[] = {
        BIO_new_mem_buf((void*) pubkeys[0], -1),
        BIO_new_mem_buf((void*) pubkeys[1], -1),
        BIO_new_mem_buf((void*) pubkeys[2], -1),
        BIO_new_mem_buf((void*) pubkeys[3], -1),
        BIO_new_mem_buf((void*) pubkeys[4], -1),
        BIO_new_mem_buf((void*) pubkeys[5], -1)
    };

    EVP_PKEY *evp_pubkeys[] = {
        PEM_read_bio_PUBKEY(bio_mems[0], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[1], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[2], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[3], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[4], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[5], NULL, NULL, NULL)
    };

    map_string_EVP_PKEY *jwt_auths = NULL;

    for(int i = 0; i < ITERS; ++i)
    {
        shput(jwt_auths, keys[i], evp_pubkeys[i]);
    }

    spiffeid_TrustDomain td = {"example.com"};
    jwtbundle_Bundle *bundle_ptr = jwtbundle_FromJWTAuthorities(td, jwt_auths);

    bool suc;
    EVP_PKEY *pkey;

    pkey = jwtbundle_Bundle_FindJWTAuthority(bundle_ptr, "key0", &suc);
    ck_assert(pkey != NULL);
    ck_assert(suc);
    ck_assert(cryptoutil_PublicKeyEqual(pkey, evp_pubkeys[0]));
    ck_assert(!cryptoutil_PublicKeyEqual(pkey, evp_pubkeys[1]));

    pkey = jwtbundle_Bundle_FindJWTAuthority(bundle_ptr, "key1", &suc);
    ck_assert(pkey != NULL);
    ck_assert(suc);
    ck_assert(!cryptoutil_PublicKeyEqual(pkey, evp_pubkeys[2]));
    ck_assert(cryptoutil_PublicKeyEqual(pkey, evp_pubkeys[1]));
    ck_assert(!cryptoutil_PublicKeyEqual(pkey, evp_pubkeys[3]));

    pkey = jwtbundle_Bundle_FindJWTAuthority(bundle_ptr, "key5", &suc);
    ck_assert(pkey != NULL);
    ck_assert(suc);
    ck_assert(!cryptoutil_PublicKeyEqual(pkey, evp_pubkeys[3]));
    ck_assert(!cryptoutil_PublicKeyEqual(pkey, evp_pubkeys[4]));
    ck_assert(cryptoutil_PublicKeyEqual(pkey, evp_pubkeys[5]));

    pkey = jwtbundle_Bundle_FindJWTAuthority(bundle_ptr, "key", &suc);
    ck_assert(pkey == NULL);
    ck_assert(!suc);

    for(int i = 0; i < ITERS; ++i)
    {
        BIO_free(bio_mems[i]);
        EVP_PKEY_free(evp_pubkeys[i]);
    }
    jwtbundle_Bundle_Free(bundle_ptr, true);
}
END_TEST

START_TEST(test_jwtbundle_Bundle_HasJWTAuthority)
{
    const int ITERS = 6;
    const char *keys[] = {
        "key0",
        "key1",
        "key2",
        "key3",
        "key4",
        "key5"
    };

    const char *pubkeys[] = {
        "-----BEGIN PUBLIC KEY-----\n"
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRFNU++93aEvz3cV8LSUP9ib3i\n"
        "UxT7SufdVXcgVFK9M3BYzvroA1uO/parFOJABTkNhTPPP/6mjrU2CPEZJ1zIkpaS\n"
        "NJrrhpp/rNMO9nyLYPGs9MfdBiWUPmHW5mY1oD0ye4my0tEsHOlgHC8AhA8OtiHr\n"
        "6IY0agXmH/y5YmSWbwIDAQAB\n"
        "-----END PUBLIC KEY-----", 
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA61BjmfXGEvWmegnBGSuS\n"
        "+rU9soUg2FnODva32D1AqhwdziwHINFaD1MVlcrYG6XRKfkcxnaXGfFDWHLEvNBS\n"
        "EVCgJjtHAGZIm5GL/KA86KDp/CwDFMSwluowcXwDwoyinmeOY9eKyh6aY72xJh7n\n"
        "oLBBq1N0bWi1e2i+83txOCg4yV2oVXhBo8pYEJ8LT3el6Smxol3C1oFMVdwPgc0v\n"
        "Tl25XucMcG/ALE/KNY6pqC2AQ6R2ERlVgPiUWOPatVkt7+Bs3h5Ramxh7XjBOXeu\n"
        "lmCpGSynXNcpZ/06+vofGi/2MlpQZNhHAo8eayMp6FcvNucIpUndo1X8dKMv3Y26\n"
        "ZQIDAQAB\n"
        "-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn/8y3uYCQxSXZ58OYceG\n"
        "A4uPdGHZXDYOQR11xcHTrH13jJEzdkYZG8irtyG+m3Jb6f9F8WkmTZxl+4YtkJdN\n"
        "9WyrKhxq4Vbt42BthadX3Ty/pKkJ81Qn8KjxWoL+SMaCGFzRlfWsFju9Q5C7+aTj\n"
        "eEKyFujH5bUTGX87nULRfg67tmtxBlT8WWWtFe2O/wedBTGGQxXMpwh4ObjLl3Qh\n"
        "bfwxlBbh2N4471TyrErv04lbNecGaQqYxGrY8Ot3l2V2fXCzghAQg26Hc4dR2wyA\n"
        "PPgWq78db+gU3QsePeo2Ki5sonkcyQQQlCkL35Asbv8khvk90gist4kijPnVBCuv\n"
        "cwIDAQAB\n"
        "-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\n"
        "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBhsFCcWY2GaiN1BjPEd1v+ESKO6/0\n"
        "D0sUR4y1amHnOr3FZx6TdqdoSBqxownQrnAKGCwagGxUb7BWwPFgHqKQJHgBq+J7\n"
        "F+6m5SKAEL1wS5pqya91N7oudF3yFW8oZRE4RQRdSLl3fV2aVXKwGDXciwhUhw8k\n"
        "x5OS4iZpMAY+LI4WVGU=\n"
        "-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\n"
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOr6rMmRRNKuZuwws/hWwFTM6ECEE\n"
        "aJGGARCJUO4UfoURl8b4JThGt8VDFKeR2i+ZxE+xh/wTBaJ/zvtSqZiNnQ==\n"
        "-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\n"
        "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEAs5xEIm001FFsRpXSRFEy57+swcr3nW9\n"
        "SP3ERlrT539LE/x2auTwUVTCkaFS6R5IBl2QIvEml+UXgBU0sDK3PqZsqHcQzvBz\n"
        "Z/lX7NehqphbVCQBr3nkhDwyq0tkrmyD\n"
        "-----END PUBLIC KEY-----"
    };

    BIO *bio_mems[] = {
        BIO_new_mem_buf((void*) pubkeys[0], -1),
        BIO_new_mem_buf((void*) pubkeys[1], -1),
        BIO_new_mem_buf((void*) pubkeys[2], -1),
        BIO_new_mem_buf((void*) pubkeys[3], -1),
        BIO_new_mem_buf((void*) pubkeys[4], -1),
        BIO_new_mem_buf((void*) pubkeys[5], -1)
    };

    EVP_PKEY *evp_pubkeys[] = {
        PEM_read_bio_PUBKEY(bio_mems[0], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[1], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[2], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[3], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[4], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[5], NULL, NULL, NULL)
    };

    map_string_EVP_PKEY *jwt_auths = NULL;

    for(int i = 0; i < ITERS; ++i)
    {
        shput(jwt_auths, keys[i], evp_pubkeys[i]);
    }

    spiffeid_TrustDomain td = {"example.com"};
    jwtbundle_Bundle *bundle_ptr = jwtbundle_FromJWTAuthorities(td, jwt_auths);

    ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, "key0"));
    ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, "key1"));
    ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, "key2"));
    ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, "key3"));
    ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, "key4"));
    ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, "key5"));
    ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, "key"));
    ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, "key6"));
    ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, "example"));
    ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, "test"));

    for(int i = 0; i < ITERS; ++i)
    {
        BIO_free(bio_mems[i]);
        EVP_PKEY_free(evp_pubkeys[i]);
    }
    jwtbundle_Bundle_Free(bundle_ptr, true);
}
END_TEST

START_TEST(test_jwtbundle_Bundle_AddJWTAuthority)
{
    const int ITERS = 6;
    const char *keys[] = {
        "key0",
        "key1",
        "key2",
        "key3",
        "key4",
        "key5"
    };

    const char *pubkeys[] = {
        "-----BEGIN PUBLIC KEY-----\n"
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRFNU++93aEvz3cV8LSUP9ib3i\n"
        "UxT7SufdVXcgVFK9M3BYzvroA1uO/parFOJABTkNhTPPP/6mjrU2CPEZJ1zIkpaS\n"
        "NJrrhpp/rNMO9nyLYPGs9MfdBiWUPmHW5mY1oD0ye4my0tEsHOlgHC8AhA8OtiHr\n"
        "6IY0agXmH/y5YmSWbwIDAQAB\n"
        "-----END PUBLIC KEY-----", 
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA61BjmfXGEvWmegnBGSuS\n"
        "+rU9soUg2FnODva32D1AqhwdziwHINFaD1MVlcrYG6XRKfkcxnaXGfFDWHLEvNBS\n"
        "EVCgJjtHAGZIm5GL/KA86KDp/CwDFMSwluowcXwDwoyinmeOY9eKyh6aY72xJh7n\n"
        "oLBBq1N0bWi1e2i+83txOCg4yV2oVXhBo8pYEJ8LT3el6Smxol3C1oFMVdwPgc0v\n"
        "Tl25XucMcG/ALE/KNY6pqC2AQ6R2ERlVgPiUWOPatVkt7+Bs3h5Ramxh7XjBOXeu\n"
        "lmCpGSynXNcpZ/06+vofGi/2MlpQZNhHAo8eayMp6FcvNucIpUndo1X8dKMv3Y26\n"
        "ZQIDAQAB\n"
        "-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn/8y3uYCQxSXZ58OYceG\n"
        "A4uPdGHZXDYOQR11xcHTrH13jJEzdkYZG8irtyG+m3Jb6f9F8WkmTZxl+4YtkJdN\n"
        "9WyrKhxq4Vbt42BthadX3Ty/pKkJ81Qn8KjxWoL+SMaCGFzRlfWsFju9Q5C7+aTj\n"
        "eEKyFujH5bUTGX87nULRfg67tmtxBlT8WWWtFe2O/wedBTGGQxXMpwh4ObjLl3Qh\n"
        "bfwxlBbh2N4471TyrErv04lbNecGaQqYxGrY8Ot3l2V2fXCzghAQg26Hc4dR2wyA\n"
        "PPgWq78db+gU3QsePeo2Ki5sonkcyQQQlCkL35Asbv8khvk90gist4kijPnVBCuv\n"
        "cwIDAQAB\n"
        "-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\n"
        "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBhsFCcWY2GaiN1BjPEd1v+ESKO6/0\n"
        "D0sUR4y1amHnOr3FZx6TdqdoSBqxownQrnAKGCwagGxUb7BWwPFgHqKQJHgBq+J7\n"
        "F+6m5SKAEL1wS5pqya91N7oudF3yFW8oZRE4RQRdSLl3fV2aVXKwGDXciwhUhw8k\n"
        "x5OS4iZpMAY+LI4WVGU=\n"
        "-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\n"
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOr6rMmRRNKuZuwws/hWwFTM6ECEE\n"
        "aJGGARCJUO4UfoURl8b4JThGt8VDFKeR2i+ZxE+xh/wTBaJ/zvtSqZiNnQ==\n"
        "-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\n"
        "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEAs5xEIm001FFsRpXSRFEy57+swcr3nW9\n"
        "SP3ERlrT539LE/x2auTwUVTCkaFS6R5IBl2QIvEml+UXgBU0sDK3PqZsqHcQzvBz\n"
        "Z/lX7NehqphbVCQBr3nkhDwyq0tkrmyD\n"
        "-----END PUBLIC KEY-----"
    };

    BIO *bio_mems[] = {
        BIO_new_mem_buf((void*) pubkeys[0], -1),
        BIO_new_mem_buf((void*) pubkeys[1], -1),
        BIO_new_mem_buf((void*) pubkeys[2], -1),
        BIO_new_mem_buf((void*) pubkeys[3], -1),
        BIO_new_mem_buf((void*) pubkeys[4], -1),
        BIO_new_mem_buf((void*) pubkeys[5], -1)
    };

    EVP_PKEY *evp_pubkeys[] = {
        PEM_read_bio_PUBKEY(bio_mems[0], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[1], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[2], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[3], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[4], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[5], NULL, NULL, NULL)
    };

    map_string_EVP_PKEY *jwt_auths = NULL;

    for(int i = 0; i < ITERS; ++i)
    {
        shput(jwt_auths, keys[i], evp_pubkeys[i]);
    }

    spiffeid_TrustDomain td = {"example.com"};
    jwtbundle_Bundle *bundle_ptr = jwtbundle_New(td);
    err_t err;
    {
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[0]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[1]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[2]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[3]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[4]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[5]));

        err = jwtbundle_Bundle_AddJWTAuthority(bundle_ptr, keys[0], evp_pubkeys[0]);
        ck_assert_uint_eq(err, NO_ERROR);
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[0]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[1]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[2]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[3]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[4]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[5]));

        err = jwtbundle_Bundle_AddJWTAuthority(bundle_ptr, keys[1], evp_pubkeys[1]);
        ck_assert_uint_eq(err, NO_ERROR);
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[0]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[1]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[2]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[3]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[4]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[5]));

        err = jwtbundle_Bundle_AddJWTAuthority(bundle_ptr, keys[2], evp_pubkeys[2]);
        ck_assert_uint_eq(err, NO_ERROR);
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[0]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[1]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[2]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[3]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[4]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[5]));

        err = jwtbundle_Bundle_AddJWTAuthority(bundle_ptr, keys[3], evp_pubkeys[3]);
        ck_assert_uint_eq(err, NO_ERROR);
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[0]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[1]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[2]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[3]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[4]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[5]));

        err = jwtbundle_Bundle_AddJWTAuthority(bundle_ptr, keys[4], evp_pubkeys[4]);
        ck_assert_uint_eq(err, NO_ERROR);
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[0]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[1]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[2]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[3]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[4]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[5]));

        err = jwtbundle_Bundle_AddJWTAuthority(bundle_ptr, keys[5], evp_pubkeys[5]);
        ck_assert_uint_eq(err, NO_ERROR);
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[0]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[1]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[2]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[3]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[4]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[5]));
    }

    for(int i = 0; i < ITERS; ++i)
    {
        BIO_free(bio_mems[i]);
        EVP_PKEY_free(evp_pubkeys[i]);
    }
    jwtbundle_Bundle_Free(bundle_ptr, true);
}
END_TEST

START_TEST(test_jwtbundle_Bundle_RemoveJWTAuthority)
{
    const int ITERS = 6;
    const char *keys[] = {
        "key0",
        "key1",
        "key2",
        "key3",
        "key4",
        "key5"
    };

    const char *pubkeys[] = {
        "-----BEGIN PUBLIC KEY-----\n"
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRFNU++93aEvz3cV8LSUP9ib3i\n"
        "UxT7SufdVXcgVFK9M3BYzvroA1uO/parFOJABTkNhTPPP/6mjrU2CPEZJ1zIkpaS\n"
        "NJrrhpp/rNMO9nyLYPGs9MfdBiWUPmHW5mY1oD0ye4my0tEsHOlgHC8AhA8OtiHr\n"
        "6IY0agXmH/y5YmSWbwIDAQAB\n"
        "-----END PUBLIC KEY-----", 
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA61BjmfXGEvWmegnBGSuS\n"
        "+rU9soUg2FnODva32D1AqhwdziwHINFaD1MVlcrYG6XRKfkcxnaXGfFDWHLEvNBS\n"
        "EVCgJjtHAGZIm5GL/KA86KDp/CwDFMSwluowcXwDwoyinmeOY9eKyh6aY72xJh7n\n"
        "oLBBq1N0bWi1e2i+83txOCg4yV2oVXhBo8pYEJ8LT3el6Smxol3C1oFMVdwPgc0v\n"
        "Tl25XucMcG/ALE/KNY6pqC2AQ6R2ERlVgPiUWOPatVkt7+Bs3h5Ramxh7XjBOXeu\n"
        "lmCpGSynXNcpZ/06+vofGi/2MlpQZNhHAo8eayMp6FcvNucIpUndo1X8dKMv3Y26\n"
        "ZQIDAQAB\n"
        "-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn/8y3uYCQxSXZ58OYceG\n"
        "A4uPdGHZXDYOQR11xcHTrH13jJEzdkYZG8irtyG+m3Jb6f9F8WkmTZxl+4YtkJdN\n"
        "9WyrKhxq4Vbt42BthadX3Ty/pKkJ81Qn8KjxWoL+SMaCGFzRlfWsFju9Q5C7+aTj\n"
        "eEKyFujH5bUTGX87nULRfg67tmtxBlT8WWWtFe2O/wedBTGGQxXMpwh4ObjLl3Qh\n"
        "bfwxlBbh2N4471TyrErv04lbNecGaQqYxGrY8Ot3l2V2fXCzghAQg26Hc4dR2wyA\n"
        "PPgWq78db+gU3QsePeo2Ki5sonkcyQQQlCkL35Asbv8khvk90gist4kijPnVBCuv\n"
        "cwIDAQAB\n"
        "-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\n"
        "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBhsFCcWY2GaiN1BjPEd1v+ESKO6/0\n"
        "D0sUR4y1amHnOr3FZx6TdqdoSBqxownQrnAKGCwagGxUb7BWwPFgHqKQJHgBq+J7\n"
        "F+6m5SKAEL1wS5pqya91N7oudF3yFW8oZRE4RQRdSLl3fV2aVXKwGDXciwhUhw8k\n"
        "x5OS4iZpMAY+LI4WVGU=\n"
        "-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\n"
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOr6rMmRRNKuZuwws/hWwFTM6ECEE\n"
        "aJGGARCJUO4UfoURl8b4JThGt8VDFKeR2i+ZxE+xh/wTBaJ/zvtSqZiNnQ==\n"
        "-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\n"
        "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEAs5xEIm001FFsRpXSRFEy57+swcr3nW9\n"
        "SP3ERlrT539LE/x2auTwUVTCkaFS6R5IBl2QIvEml+UXgBU0sDK3PqZsqHcQzvBz\n"
        "Z/lX7NehqphbVCQBr3nkhDwyq0tkrmyD\n"
        "-----END PUBLIC KEY-----"
    };

    BIO *bio_mems[] = {
        BIO_new_mem_buf((void*) pubkeys[0], -1),
        BIO_new_mem_buf((void*) pubkeys[1], -1),
        BIO_new_mem_buf((void*) pubkeys[2], -1),
        BIO_new_mem_buf((void*) pubkeys[3], -1),
        BIO_new_mem_buf((void*) pubkeys[4], -1),
        BIO_new_mem_buf((void*) pubkeys[5], -1)
    };

    EVP_PKEY *evp_pubkeys[] = {
        PEM_read_bio_PUBKEY(bio_mems[0], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[1], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[2], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[3], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[4], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[5], NULL, NULL, NULL)
    };

    map_string_EVP_PKEY *jwt_auths = NULL;

    for(int i = 0; i < ITERS; ++i)
    {
        shput(jwt_auths, keys[i], evp_pubkeys[i]);
    }

    spiffeid_TrustDomain td = {"example.com"};
    jwtbundle_Bundle *bundle_ptr = jwtbundle_FromJWTAuthorities(td, jwt_auths);

    {
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[0]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[1]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[2]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[3]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[4]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[5]));

        jwtbundle_Bundle_RemoveJWTAuthority(bundle_ptr, keys[0]);
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[0]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[1]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[2]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[3]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[4]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[5]));

        jwtbundle_Bundle_RemoveJWTAuthority(bundle_ptr, keys[1]);
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[0]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[1]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[2]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[3]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[4]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[5]));

        jwtbundle_Bundle_RemoveJWTAuthority(bundle_ptr, keys[2]);
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[0]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[1]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[2]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[3]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[4]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[5]));

        jwtbundle_Bundle_RemoveJWTAuthority(bundle_ptr, keys[3]);
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[0]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[1]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[2]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[3]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[4]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[5]));

        jwtbundle_Bundle_RemoveJWTAuthority(bundle_ptr, keys[4]);
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[0]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[1]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[2]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[3]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[4]));
        ck_assert(jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[5]));

        jwtbundle_Bundle_RemoveJWTAuthority(bundle_ptr, keys[5]);
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[0]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[1]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[2]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[3]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[4]));
        ck_assert(!jwtbundle_Bundle_HasJWTAuthority(bundle_ptr, keys[5]));
    }

    for(int i = 0; i < ITERS; ++i)
    {
        BIO_free(bio_mems[i]);
        EVP_PKEY_free(evp_pubkeys[i]);
    }
    jwtbundle_Bundle_Free(bundle_ptr, true);
}
END_TEST

START_TEST(test_jwtbundle_Bundle_SetJWTAuthorities)
{
    const int ITERS = 6;
    const char *keys[] = {
        "key0",
        "key1",
        "key2",
        "key3",
        "key4",
        "key5"
    };

    const char *pubkeys[] = {
        "-----BEGIN PUBLIC KEY-----\n"
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRFNU++93aEvz3cV8LSUP9ib3i\n"
        "UxT7SufdVXcgVFK9M3BYzvroA1uO/parFOJABTkNhTPPP/6mjrU2CPEZJ1zIkpaS\n"
        "NJrrhpp/rNMO9nyLYPGs9MfdBiWUPmHW5mY1oD0ye4my0tEsHOlgHC8AhA8OtiHr\n"
        "6IY0agXmH/y5YmSWbwIDAQAB\n"
        "-----END PUBLIC KEY-----", 
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA61BjmfXGEvWmegnBGSuS\n"
        "+rU9soUg2FnODva32D1AqhwdziwHINFaD1MVlcrYG6XRKfkcxnaXGfFDWHLEvNBS\n"
        "EVCgJjtHAGZIm5GL/KA86KDp/CwDFMSwluowcXwDwoyinmeOY9eKyh6aY72xJh7n\n"
        "oLBBq1N0bWi1e2i+83txOCg4yV2oVXhBo8pYEJ8LT3el6Smxol3C1oFMVdwPgc0v\n"
        "Tl25XucMcG/ALE/KNY6pqC2AQ6R2ERlVgPiUWOPatVkt7+Bs3h5Ramxh7XjBOXeu\n"
        "lmCpGSynXNcpZ/06+vofGi/2MlpQZNhHAo8eayMp6FcvNucIpUndo1X8dKMv3Y26\n"
        "ZQIDAQAB\n"
        "-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn/8y3uYCQxSXZ58OYceG\n"
        "A4uPdGHZXDYOQR11xcHTrH13jJEzdkYZG8irtyG+m3Jb6f9F8WkmTZxl+4YtkJdN\n"
        "9WyrKhxq4Vbt42BthadX3Ty/pKkJ81Qn8KjxWoL+SMaCGFzRlfWsFju9Q5C7+aTj\n"
        "eEKyFujH5bUTGX87nULRfg67tmtxBlT8WWWtFe2O/wedBTGGQxXMpwh4ObjLl3Qh\n"
        "bfwxlBbh2N4471TyrErv04lbNecGaQqYxGrY8Ot3l2V2fXCzghAQg26Hc4dR2wyA\n"
        "PPgWq78db+gU3QsePeo2Ki5sonkcyQQQlCkL35Asbv8khvk90gist4kijPnVBCuv\n"
        "cwIDAQAB\n"
        "-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\n"
        "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBhsFCcWY2GaiN1BjPEd1v+ESKO6/0\n"
        "D0sUR4y1amHnOr3FZx6TdqdoSBqxownQrnAKGCwagGxUb7BWwPFgHqKQJHgBq+J7\n"
        "F+6m5SKAEL1wS5pqya91N7oudF3yFW8oZRE4RQRdSLl3fV2aVXKwGDXciwhUhw8k\n"
        "x5OS4iZpMAY+LI4WVGU=\n"
        "-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\n"
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOr6rMmRRNKuZuwws/hWwFTM6ECEE\n"
        "aJGGARCJUO4UfoURl8b4JThGt8VDFKeR2i+ZxE+xh/wTBaJ/zvtSqZiNnQ==\n"
        "-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\n"
        "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEAs5xEIm001FFsRpXSRFEy57+swcr3nW9\n"
        "SP3ERlrT539LE/x2auTwUVTCkaFS6R5IBl2QIvEml+UXgBU0sDK3PqZsqHcQzvBz\n"
        "Z/lX7NehqphbVCQBr3nkhDwyq0tkrmyD\n"
        "-----END PUBLIC KEY-----"
    };

    BIO *bio_mems[] = {
        BIO_new_mem_buf((void*) pubkeys[0], -1),
        BIO_new_mem_buf((void*) pubkeys[1], -1),
        BIO_new_mem_buf((void*) pubkeys[2], -1),
        BIO_new_mem_buf((void*) pubkeys[3], -1),
        BIO_new_mem_buf((void*) pubkeys[4], -1),
        BIO_new_mem_buf((void*) pubkeys[5], -1)
    };

    EVP_PKEY *evp_pubkeys[] = {
        PEM_read_bio_PUBKEY(bio_mems[0], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[1], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[2], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[3], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[4], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[5], NULL, NULL, NULL)
    };

    map_string_EVP_PKEY *jwt_auths = NULL;

    for(int i = 0; i < ITERS; ++i)
    {
        shput(jwt_auths, keys[i], evp_pubkeys[i]);
    }

    spiffeid_TrustDomain td = {"example.com"};
    jwtbundle_Bundle *bundle_ptr = jwtbundle_New(td);
    jwtbundle_Bundle_SetJWTAuthorities(bundle_ptr, jwt_auths);

    ck_assert(jwtutil_JWTAuthoritiesEqual(jwt_auths, bundle_ptr->auths));

    for(int i = 0; i < ITERS; ++i)
    {
        BIO_free(bio_mems[i]);
        EVP_PKEY_free(evp_pubkeys[i]);
    }
    jwtbundle_Bundle_Free(bundle_ptr, true);
}
END_TEST

START_TEST(test_jwtbundle_Bundle_Empty)
{
    const int ITERS = 6;
    const char *keys[] = {
        "key0",
        "key1",
        "key2",
        "key3",
        "key4",
        "key5"
    };

    const char *pubkeys[] = {
        "-----BEGIN PUBLIC KEY-----\n"
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRFNU++93aEvz3cV8LSUP9ib3i\n"
        "UxT7SufdVXcgVFK9M3BYzvroA1uO/parFOJABTkNhTPPP/6mjrU2CPEZJ1zIkpaS\n"
        "NJrrhpp/rNMO9nyLYPGs9MfdBiWUPmHW5mY1oD0ye4my0tEsHOlgHC8AhA8OtiHr\n"
        "6IY0agXmH/y5YmSWbwIDAQAB\n"
        "-----END PUBLIC KEY-----", 
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA61BjmfXGEvWmegnBGSuS\n"
        "+rU9soUg2FnODva32D1AqhwdziwHINFaD1MVlcrYG6XRKfkcxnaXGfFDWHLEvNBS\n"
        "EVCgJjtHAGZIm5GL/KA86KDp/CwDFMSwluowcXwDwoyinmeOY9eKyh6aY72xJh7n\n"
        "oLBBq1N0bWi1e2i+83txOCg4yV2oVXhBo8pYEJ8LT3el6Smxol3C1oFMVdwPgc0v\n"
        "Tl25XucMcG/ALE/KNY6pqC2AQ6R2ERlVgPiUWOPatVkt7+Bs3h5Ramxh7XjBOXeu\n"
        "lmCpGSynXNcpZ/06+vofGi/2MlpQZNhHAo8eayMp6FcvNucIpUndo1X8dKMv3Y26\n"
        "ZQIDAQAB\n"
        "-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn/8y3uYCQxSXZ58OYceG\n"
        "A4uPdGHZXDYOQR11xcHTrH13jJEzdkYZG8irtyG+m3Jb6f9F8WkmTZxl+4YtkJdN\n"
        "9WyrKhxq4Vbt42BthadX3Ty/pKkJ81Qn8KjxWoL+SMaCGFzRlfWsFju9Q5C7+aTj\n"
        "eEKyFujH5bUTGX87nULRfg67tmtxBlT8WWWtFe2O/wedBTGGQxXMpwh4ObjLl3Qh\n"
        "bfwxlBbh2N4471TyrErv04lbNecGaQqYxGrY8Ot3l2V2fXCzghAQg26Hc4dR2wyA\n"
        "PPgWq78db+gU3QsePeo2Ki5sonkcyQQQlCkL35Asbv8khvk90gist4kijPnVBCuv\n"
        "cwIDAQAB\n"
        "-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\n"
        "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBhsFCcWY2GaiN1BjPEd1v+ESKO6/0\n"
        "D0sUR4y1amHnOr3FZx6TdqdoSBqxownQrnAKGCwagGxUb7BWwPFgHqKQJHgBq+J7\n"
        "F+6m5SKAEL1wS5pqya91N7oudF3yFW8oZRE4RQRdSLl3fV2aVXKwGDXciwhUhw8k\n"
        "x5OS4iZpMAY+LI4WVGU=\n"
        "-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\n"
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOr6rMmRRNKuZuwws/hWwFTM6ECEE\n"
        "aJGGARCJUO4UfoURl8b4JThGt8VDFKeR2i+ZxE+xh/wTBaJ/zvtSqZiNnQ==\n"
        "-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\n"
        "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEAs5xEIm001FFsRpXSRFEy57+swcr3nW9\n"
        "SP3ERlrT539LE/x2auTwUVTCkaFS6R5IBl2QIvEml+UXgBU0sDK3PqZsqHcQzvBz\n"
        "Z/lX7NehqphbVCQBr3nkhDwyq0tkrmyD\n"
        "-----END PUBLIC KEY-----"
    };

    BIO *bio_mems[] = {
        BIO_new_mem_buf((void*) pubkeys[0], -1),
        BIO_new_mem_buf((void*) pubkeys[1], -1),
        BIO_new_mem_buf((void*) pubkeys[2], -1),
        BIO_new_mem_buf((void*) pubkeys[3], -1),
        BIO_new_mem_buf((void*) pubkeys[4], -1),
        BIO_new_mem_buf((void*) pubkeys[5], -1)
    };

    EVP_PKEY *evp_pubkeys[] = {
        PEM_read_bio_PUBKEY(bio_mems[0], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[1], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[2], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[3], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[4], NULL, NULL, NULL),
        PEM_read_bio_PUBKEY(bio_mems[5], NULL, NULL, NULL)
    };

    map_string_EVP_PKEY *jwt_auths = NULL;

    for(int i = 0; i < ITERS; ++i)
    {
        shput(jwt_auths, keys[i], evp_pubkeys[i]);
    }

    spiffeid_TrustDomain td = {"example.com"};
    jwtbundle_Bundle *bundle_ptr = jwtbundle_New(td);

    ck_assert(jwtbundle_Bundle_Empty(bundle_ptr));
    jwtbundle_Bundle_SetJWTAuthorities(bundle_ptr, jwt_auths);
    ck_assert(!jwtbundle_Bundle_Empty(bundle_ptr));

    for(int i = 0; i < ITERS; ++i)
    {
        BIO_free(bio_mems[i]);
        EVP_PKEY_free(evp_pubkeys[i]);
    }
    jwtbundle_Bundle_Free(bundle_ptr, true);
}
END_TEST

START_TEST(test_jwtbundle_Bundle_Clone)
{
    spiffeid_TrustDomain td = {"example.com"};
    err_t err;

    jwtbundle_Bundle *bundle_ptr = jwtbundle_Load(td, "jwk_keys.json", &err);
    jwtbundle_Bundle *copy_ptr = jwtbundle_Bundle_Clone(bundle_ptr);

    ck_assert_str_eq(bundle_ptr->td.name, copy_ptr->td.name);
    ck_assert(jwtutil_JWTAuthoritiesEqual(bundle_ptr->auths, copy_ptr->auths));

    jwtbundle_Bundle_Free(bundle_ptr, true);
    jwtbundle_Bundle_Free(copy_ptr, true);
}
END_TEST

START_TEST(test_jwtbundle_Bundle_Equal)
{
    spiffeid_TrustDomain td = {"example.com"};
    err_t err;

    jwtbundle_Bundle *bundle_ptr = jwtbundle_Load(td, "jwk_keys.json", &err);
    jwtbundle_Bundle *bundle2_ptr = jwtbundle_Bundle_Clone(bundle_ptr);

    ck_assert(jwtbundle_Bundle_Equal(bundle_ptr, bundle2_ptr));
    jwtbundle_Bundle_RemoveJWTAuthority(bundle2_ptr, "79c809dd1186cc228c4baf9358599530ce92b4c8");
    ck_assert(!jwtbundle_Bundle_Equal(bundle_ptr, bundle2_ptr));

    jwtbundle_Bundle_Free(bundle_ptr, true);
    jwtbundle_Bundle_Free(bundle2_ptr, true);
}
END_TEST

START_TEST(test_jwtbundle_Bundle_GetJWTBundleForTrustDomain)
{
    spiffeid_TrustDomain td = {"example.com"};
    err_t err;

    jwtbundle_Bundle *bundle_ptr = jwtbundle_Load(td, "jwk_keys.json", &err);
    
    jwtbundle_Bundle *bundle_td = jwtbundle_Bundle_GetJWTBundleForTrustDomain(
                                    bundle_ptr,
                                    (spiffeid_TrustDomain){"example.com"},
                                    &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_eq(bundle_ptr, bundle_td); 

    bundle_td = jwtbundle_Bundle_GetJWTBundleForTrustDomain(
                    bundle_ptr,
                    (spiffeid_TrustDomain){"example1.com"},
                    &err);
    
    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert_ptr_ne(bundle_ptr, bundle_td); 

    jwtbundle_Bundle_Free(bundle_ptr, true);
}
END_TEST

Suite* bundle_suite(void)
{
    Suite *s = suite_create("bundle");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_jwtbundle_New);
    tcase_add_test(tc_core, test_jwtbundle_Parse);
    tcase_add_test(tc_core, test_jwtbundle_Load);
    tcase_add_test(tc_core, test_jwtbundle_FromJWTAuthorities);
    tcase_add_test(tc_core, test_jwtbundle_Bundle_JWTAuthorities);
    tcase_add_test(tc_core, test_jwtbundle_Bundle_FindJWTAuthority);
    tcase_add_test(tc_core, test_jwtbundle_Bundle_HasJWTAuthority);
    tcase_add_test(tc_core, test_jwtbundle_Bundle_AddJWTAuthority);
    tcase_add_test(tc_core, test_jwtbundle_Bundle_RemoveJWTAuthority);
    tcase_add_test(tc_core, test_jwtbundle_Bundle_SetJWTAuthorities);
    tcase_add_test(tc_core, test_jwtbundle_Bundle_Empty);
    tcase_add_test(tc_core, test_jwtbundle_Bundle_Clone);
    tcase_add_test(tc_core, test_jwtbundle_Bundle_Equal);
    tcase_add_test(tc_core, test_jwtbundle_Bundle_GetJWTBundleForTrustDomain);

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