#include "internal/jwtutil/src/util.h"
#include <check.h>
#include <openssl/pem.h>

#define STB_DS_IMPLEMENTATION
#include "utils/src/stb_ds.h"

START_TEST(test_jwtutil_JWTAuthoritiesEqual)
{
    const int ITERS = 6;
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

    BIO *bio_mems[] = { BIO_new_mem_buf((void *) pubkeys[0], -1),
                        BIO_new_mem_buf((void *) pubkeys[1], -1),
                        BIO_new_mem_buf((void *) pubkeys[2], -1),
                        BIO_new_mem_buf((void *) pubkeys[3], -1),
                        BIO_new_mem_buf((void *) pubkeys[4], -1),
                        BIO_new_mem_buf((void *) pubkeys[5], -1) };

    EVP_PKEY *evp_pubkeys[]
        = { PEM_read_bio_PUBKEY(bio_mems[0], NULL, NULL, NULL),
            PEM_read_bio_PUBKEY(bio_mems[1], NULL, NULL, NULL),
            PEM_read_bio_PUBKEY(bio_mems[2], NULL, NULL, NULL),
            PEM_read_bio_PUBKEY(bio_mems[3], NULL, NULL, NULL),
            PEM_read_bio_PUBKEY(bio_mems[4], NULL, NULL, NULL),
            PEM_read_bio_PUBKEY(bio_mems[5], NULL, NULL, NULL) };

    map_string_EVP_PKEY *str_evp0 = NULL;
    map_string_EVP_PKEY *str_evp1 = NULL;

    ck_assert(jwtutil_JWTAuthoritiesEqual(str_evp0, str_evp1));
    ck_assert(jwtutil_JWTAuthoritiesEqual(str_evp1, str_evp0));

    shput(str_evp0, "key1", evp_pubkeys[1]);
    shput(str_evp1, "key0", evp_pubkeys[0]);
    ck_assert(!jwtutil_JWTAuthoritiesEqual(str_evp0, str_evp1));
    ck_assert(!jwtutil_JWTAuthoritiesEqual(str_evp1, str_evp0));

    shput(str_evp0, "key0", evp_pubkeys[0]);
    shput(str_evp1, "key1", evp_pubkeys[1]);
    ck_assert(jwtutil_JWTAuthoritiesEqual(str_evp0, str_evp1));
    ck_assert(jwtutil_JWTAuthoritiesEqual(str_evp1, str_evp0));

    shput(str_evp0, "key5", evp_pubkeys[5]);
    shput(str_evp0, "key3", evp_pubkeys[3]);
    ck_assert(!jwtutil_JWTAuthoritiesEqual(str_evp0, str_evp1));
    ck_assert(!jwtutil_JWTAuthoritiesEqual(str_evp1, str_evp0));

    shput(str_evp1, "key3", evp_pubkeys[3]);
    shput(str_evp1, "key5", evp_pubkeys[5]);
    ck_assert(jwtutil_JWTAuthoritiesEqual(str_evp0, str_evp1));
    ck_assert(jwtutil_JWTAuthoritiesEqual(str_evp1, str_evp0));

    shput(str_evp0, "key2", evp_pubkeys[2]);
    ck_assert(!jwtutil_JWTAuthoritiesEqual(str_evp0, str_evp1));
    ck_assert(!jwtutil_JWTAuthoritiesEqual(str_evp1, str_evp0));

    shput(str_evp1, "key2", evp_pubkeys[2]);
    ck_assert(jwtutil_JWTAuthoritiesEqual(str_evp0, str_evp1));
    ck_assert(jwtutil_JWTAuthoritiesEqual(str_evp1, str_evp0));

    for(int i = 0; i < ITERS; ++i) {
        BIO_free(bio_mems[i]);
        EVP_PKEY_free(evp_pubkeys[i]);
    }
    shfree(str_evp0);
    shfree(str_evp1);
}
END_TEST

START_TEST(test_jwtutil_CopyJWTAuthorities)
{
    const int ITERS = 6;
    const char *keys[] = { "key0", "key1", "key2", "key3", "key4", "key5" };

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

    BIO *bio_mems[] = { BIO_new_mem_buf((void *) pubkeys[0], -1),
                        BIO_new_mem_buf((void *) pubkeys[1], -1),
                        BIO_new_mem_buf((void *) pubkeys[2], -1),
                        BIO_new_mem_buf((void *) pubkeys[3], -1),
                        BIO_new_mem_buf((void *) pubkeys[4], -1),
                        BIO_new_mem_buf((void *) pubkeys[5], -1) };

    EVP_PKEY *evp_pubkeys[]
        = { PEM_read_bio_PUBKEY(bio_mems[0], NULL, NULL, NULL),
            PEM_read_bio_PUBKEY(bio_mems[1], NULL, NULL, NULL),
            PEM_read_bio_PUBKEY(bio_mems[2], NULL, NULL, NULL),
            PEM_read_bio_PUBKEY(bio_mems[3], NULL, NULL, NULL),
            PEM_read_bio_PUBKEY(bio_mems[4], NULL, NULL, NULL),
            PEM_read_bio_PUBKEY(bio_mems[5], NULL, NULL, NULL) };

    map_string_EVP_PKEY *str_evp0 = NULL;

    for(int i = 0; i < ITERS; ++i) {
        shput(str_evp0, keys[i], evp_pubkeys[i]);
    }

    map_string_EVP_PKEY *str_evp1 = jwtutil_CopyJWTAuthorities(str_evp0);

    ck_assert(jwtutil_JWTAuthoritiesEqual(str_evp0, str_evp1));

    for(int i = 0; i < ITERS; ++i) {
        BIO_free(bio_mems[i]);
    }

    for(size_t i = 0, size = shlenu(str_evp0); i < size; ++i) {
        EVP_PKEY_free(str_evp0[i].value);
        EVP_PKEY_free(str_evp1[i].value);
    }
    shfree(str_evp0);
    shfree(str_evp1);
}
END_TEST

Suite *util_suite(void)
{
    Suite *s = suite_create("util");
    TCase *tc_core = tcase_create("core");

    suite_add_tcase(s, tc_core);

    tcase_add_test(tc_core, test_jwtutil_JWTAuthoritiesEqual);
    tcase_add_test(tc_core, test_jwtutil_CopyJWTAuthorities);

    return s;
}

int main(void)
{
    Suite *s = util_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
