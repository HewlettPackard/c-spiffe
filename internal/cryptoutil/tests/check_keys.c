#include "c-spiffe/internal/cryptoutil/keys.h"
#include <check.h>
#include <openssl/pem.h>

START_TEST(test_cryptoutil_RSAPublicKeyEqual)
{
    const char pubkey_bytes1[]
        = "-----BEGIN RSA PUBLIC KEY-----\n"
          "MIIBCgKCAQEA+xGZ/wcz9ugFpP07Nspo6U17l0YhFiFpxxU4pTk3Lifz9R3zsIsu\n"
          "ERwta7+fWIfxOo208ett/jhskiVodSEt3QBGh4XBipyWopKwZ93HHaDVZAALi/2A\n"
          "+xTBtWdEo7XGUujKDvC2/aZKukfjpOiUI8AhLAfjmlcD/UZ1QPh0mHsglRNCmpCw\n"
          "mwSXA9VNmhz+PiB+Dml4WWnKW/VHo2ujTXxq7+efMU4H2fny3Se3KYOsFPFGZ1TN\n"
          "QSYlFuShWrHPtiLmUdPoP6CV2mML1tk+l7DIIqXrQhLUKDACeM5roMx0kLhUWB8P\n"
          "+0uj1CNlNN4JRZlC7xFfqiMbFRU9Z4N6YwIDAQAB\n"
          "-----END RSA PUBLIC KEY-----";
    const int pubkey_len1 = strlen(pubkey_bytes1);

    const char pubkey_bytes2[]
        = "-----BEGIN RSA PUBLIC KEY-----\n"
          "MIIBCgKCAQEA0cgFv6wEcqoOhPtHdVmX4YFlCwodnSqooeCxFF1XadTS4sZkVJTC\n"
          "kszHmRqXiXL2NmqnuDQsq6nLd+sNoU5yJJ+W1hwo7UToCyJ/81tS4n6mXvF8oilP\n"
          "8YudD5QnBdW9LhqttBIN4Gk+Cxun+HG1rSJLGP9yiPPFd7DPiFz0Gd+juyWznWnP\n"
          "gapDIWEKqANKma3j6b9eopBDWB0XAgU0HQ71MSNbcsPvDd23Ftx0re/7jG53V7Bn\n"
          "eBy7fQsPmxcn4c74Lz4CvhOr7VdQpeBzNeG2CtkefKWyTk7Vu4FZnAgNd/202XAr\n"
          "c6GmEQqD2M2zXH/nVZg5oLznECDVQ1x/pwIDAQAB\n"
          "-----END RSA PUBLIC KEY-----";
    const int pubkey_len2 = strlen(pubkey_bytes2);

    const char pubkey_bytes3[]
        = "-----BEGIN PUBLIC KEY-----\n"
          "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn/8y3uYCQxSXZ58OYceG\n"
          "A4uPdGHZXDYOQR11xcHTrH13jJEzdkYZG8irtyG+m3Jb6f9F8WkmTZxl+4YtkJdN\n"
          "9WyrKhxq4Vbt42BthadX3Ty/pKkJ81Qn8KjxWoL+SMaCGFzRlfWsFju9Q5C7+aTj\n"
          "eEKyFujH5bUTGX87nULRfg67tmtxBlT8WWWtFe2O/wedBTGGQxXMpwh4ObjLl3Qh\n"
          "bfwxlBbh2N4471TyrErv04lbNecGaQqYxGrY8Ot3l2V2fXCzghAQg26Hc4dR2wyA\n"
          "PPgWq78db+gU3QsePeo2Ki5sonkcyQQQlCkL35Asbv8khvk90gist4kijPnVBCuv\n"
          "cwIDAQAB\n"
          "-----END PUBLIC KEY-----";
    const int pubkey_len3 = strlen(pubkey_bytes3);

    BIO *bio_mem;

    bio_mem = BIO_new_mem_buf((void *) pubkey_bytes1, pubkey_len1);
    RSA *rsa_pubkey1 = PEM_read_bio_RSAPublicKey(bio_mem, NULL, NULL, NULL);

    BIO_free(bio_mem);

    bio_mem = BIO_new_mem_buf((void *) pubkey_bytes2, pubkey_len2);
    RSA *rsa_pubkey2 = PEM_read_bio_RSAPublicKey(bio_mem, NULL, NULL, NULL);

    BIO_free(bio_mem);

    bio_mem = BIO_new_mem_buf((void *) pubkey_bytes3, pubkey_len3);
    EVP_PKEY *evp_pubkey = PEM_read_bio_PUBKEY(bio_mem, NULL, NULL, NULL);
    RSA *rsa_pubkey3 = EVP_PKEY_get1_RSA(evp_pubkey);

    BIO_free(bio_mem);

    ck_assert(rsa_pubkey1 != NULL);
    ck_assert(rsa_pubkey2 != NULL);
    ck_assert(rsa_pubkey3 != NULL);
    ck_assert(evp_pubkey != NULL);

    ck_assert(!cryptoutil_RSAPublicKeyEqual(rsa_pubkey1, rsa_pubkey2));
    ck_assert(!cryptoutil_RSAPublicKeyEqual(rsa_pubkey1, rsa_pubkey3));
    ck_assert(!cryptoutil_RSAPublicKeyEqual(rsa_pubkey2, rsa_pubkey3));

    ck_assert(cryptoutil_RSAPublicKeyEqual(rsa_pubkey1, rsa_pubkey1));
    ck_assert(cryptoutil_RSAPublicKeyEqual(rsa_pubkey2, rsa_pubkey2));
    ck_assert(cryptoutil_RSAPublicKeyEqual(rsa_pubkey3, rsa_pubkey3));

    RSA_free(rsa_pubkey1);
    RSA_free(rsa_pubkey2);
    RSA_free(rsa_pubkey3);
    EVP_PKEY_free(evp_pubkey);
}
END_TEST

START_TEST(test_cryptoutil_ECDSAPublicKeyEqual)
{
    const char pubkey_bytes1[]
        = "-----BEGIN PUBLIC KEY-----\n"
          "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBhsFCcWY2GaiN1BjPEd1v+ESKO6/0\n"
          "D0sUR4y1amHnOr3FZx6TdqdoSBqxownQrnAKGCwagGxUb7BWwPFgHqKQJHgBq+J7\n"
          "F+6m5SKAEL1wS5pqya91N7oudF3yFW8oZRE4RQRdSLl3fV2aVXKwGDXciwhUhw8k\n"
          "x5OS4iZpMAY+LI4WVGU=\n"
          "-----END PUBLIC KEY-----";
    const int pubkey_len1 = strlen(pubkey_bytes1);

    const char pubkey_bytes2[]
        = "-----BEGIN PUBLIC KEY-----\n"
          "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOr6rMmRRNKuZuwws/hWwFTM6ECEE\n"
          "aJGGARCJUO4UfoURl8b4JThGt8VDFKeR2i+ZxE+xh/wTBaJ/zvtSqZiNnQ==\n"
          "-----END PUBLIC KEY-----";
    const int pubkey_len2 = strlen(pubkey_bytes2);

    const char pubkey_bytes3[]
        = "-----BEGIN PUBLIC KEY-----\n"
          "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEAs5xEIm001FFsRpXSRFEy57+swcr3nW9\n"
          "SP3ERlrT539LE/x2auTwUVTCkaFS6R5IBl2QIvEml+UXgBU0sDK3PqZsqHcQzvBz\n"
          "Z/lX7NehqphbVCQBr3nkhDwyq0tkrmyD\n"
          "-----END PUBLIC KEY-----";
    const int pubkey_len3 = strlen(pubkey_bytes3);

    BIO *bio_mem;

    bio_mem = BIO_new_mem_buf((void *) pubkey_bytes1, pubkey_len1);
    EC_KEY *ec_pubkey1 = PEM_read_bio_EC_PUBKEY(bio_mem, NULL, NULL, NULL);

    BIO_free(bio_mem);

    bio_mem = BIO_new_mem_buf((void *) pubkey_bytes2, pubkey_len2);
    EC_KEY *ec_pubkey2 = PEM_read_bio_EC_PUBKEY(bio_mem, NULL, NULL, NULL);

    BIO_free(bio_mem);

    bio_mem = BIO_new_mem_buf((void *) pubkey_bytes3, pubkey_len3);
    EC_KEY *ec_pubkey3 = PEM_read_bio_EC_PUBKEY(bio_mem, NULL, NULL, NULL);

    BIO_free(bio_mem);

    ck_assert(ec_pubkey1 != NULL);
    ck_assert(ec_pubkey2 != NULL);
    ck_assert(ec_pubkey3 != NULL);

    ck_assert(!cryptoutil_ECDSAPublicKeyEqual(ec_pubkey1, ec_pubkey2));
    ck_assert(!cryptoutil_ECDSAPublicKeyEqual(ec_pubkey1, ec_pubkey3));
    ck_assert(!cryptoutil_ECDSAPublicKeyEqual(ec_pubkey2, ec_pubkey3));

    ck_assert(cryptoutil_ECDSAPublicKeyEqual(ec_pubkey1, ec_pubkey1));
    ck_assert(cryptoutil_ECDSAPublicKeyEqual(ec_pubkey2, ec_pubkey2));
    ck_assert(cryptoutil_ECDSAPublicKeyEqual(ec_pubkey3, ec_pubkey3));

    EC_KEY_free(ec_pubkey1);
    EC_KEY_free(ec_pubkey2);
    EC_KEY_free(ec_pubkey3);
}
END_TEST

START_TEST(test_cryptoutil_PublicKeyEqual)
{
    const char rsa_pubkey_bytes1[]
        = "-----BEGIN PUBLIC KEY-----\n"
          "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRFNU++93aEvz3cV8LSUP9ib3i\n"
          "UxT7SufdVXcgVFK9M3BYzvroA1uO/parFOJABTkNhTPPP/6mjrU2CPEZJ1zIkpaS\n"
          "NJrrhpp/rNMO9nyLYPGs9MfdBiWUPmHW5mY1oD0ye4my0tEsHOlgHC8AhA8OtiHr\n"
          "6IY0agXmH/y5YmSWbwIDAQAB\n"
          "-----END PUBLIC KEY-----";
    const int rsa_pubkey_len1 = strlen(rsa_pubkey_bytes1);

    const char rsa_pubkey_bytes2[]
        = "-----BEGIN PUBLIC KEY-----\n"
          "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA61BjmfXGEvWmegnBGSuS\n"
          "+rU9soUg2FnODva32D1AqhwdziwHINFaD1MVlcrYG6XRKfkcxnaXGfFDWHLEvNBS\n"
          "EVCgJjtHAGZIm5GL/KA86KDp/CwDFMSwluowcXwDwoyinmeOY9eKyh6aY72xJh7n\n"
          "oLBBq1N0bWi1e2i+83txOCg4yV2oVXhBo8pYEJ8LT3el6Smxol3C1oFMVdwPgc0v\n"
          "Tl25XucMcG/ALE/KNY6pqC2AQ6R2ERlVgPiUWOPatVkt7+Bs3h5Ramxh7XjBOXeu\n"
          "lmCpGSynXNcpZ/06+vofGi/2MlpQZNhHAo8eayMp6FcvNucIpUndo1X8dKMv3Y26\n"
          "ZQIDAQAB\n"
          "-----END PUBLIC KEY-----";
    const int rsa_pubkey_len2 = strlen(rsa_pubkey_bytes2);

    const char rsa_pubkey_bytes3[]
        = "-----BEGIN PUBLIC KEY-----\n"
          "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn/8y3uYCQxSXZ58OYceG\n"
          "A4uPdGHZXDYOQR11xcHTrH13jJEzdkYZG8irtyG+m3Jb6f9F8WkmTZxl+4YtkJdN\n"
          "9WyrKhxq4Vbt42BthadX3Ty/pKkJ81Qn8KjxWoL+SMaCGFzRlfWsFju9Q5C7+aTj\n"
          "eEKyFujH5bUTGX87nULRfg67tmtxBlT8WWWtFe2O/wedBTGGQxXMpwh4ObjLl3Qh\n"
          "bfwxlBbh2N4471TyrErv04lbNecGaQqYxGrY8Ot3l2V2fXCzghAQg26Hc4dR2wyA\n"
          "PPgWq78db+gU3QsePeo2Ki5sonkcyQQQlCkL35Asbv8khvk90gist4kijPnVBCuv\n"
          "cwIDAQAB\n"
          "-----END PUBLIC KEY-----";
    const int rsa_pubkey_len3 = strlen(rsa_pubkey_bytes3);

    const char ecdsa_pubkey_bytes1[]
        = "-----BEGIN PUBLIC KEY-----\n"
          "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBhsFCcWY2GaiN1BjPEd1v+ESKO6/0\n"
          "D0sUR4y1amHnOr3FZx6TdqdoSBqxownQrnAKGCwagGxUb7BWwPFgHqKQJHgBq+J7\n"
          "F+6m5SKAEL1wS5pqya91N7oudF3yFW8oZRE4RQRdSLl3fV2aVXKwGDXciwhUhw8k\n"
          "x5OS4iZpMAY+LI4WVGU=\n"
          "-----END PUBLIC KEY-----";
    const int ecdsa_pubkey_len1 = strlen(ecdsa_pubkey_bytes1);

    const char ecdsa_pubkey_bytes2[]
        = "-----BEGIN PUBLIC KEY-----\n"
          "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOr6rMmRRNKuZuwws/hWwFTM6ECEE\n"
          "aJGGARCJUO4UfoURl8b4JThGt8VDFKeR2i+ZxE+xh/wTBaJ/zvtSqZiNnQ==\n"
          "-----END PUBLIC KEY-----";
    const int ecdsa_pubkey_len2 = strlen(ecdsa_pubkey_bytes2);

    const char ecdsa_pubkey_bytes3[]
        = "-----BEGIN PUBLIC KEY-----\n"
          "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEAs5xEIm001FFsRpXSRFEy57+swcr3nW9\n"
          "SP3ERlrT539LE/x2auTwUVTCkaFS6R5IBl2QIvEml+UXgBU0sDK3PqZsqHcQzvBz\n"
          "Z/lX7NehqphbVCQBr3nkhDwyq0tkrmyD\n"
          "-----END PUBLIC KEY-----";
    const int ecdsa_pubkey_len3 = strlen(ecdsa_pubkey_bytes3);

    BIO *bio_mem;

    bio_mem = BIO_new_mem_buf((void *) rsa_pubkey_bytes1, rsa_pubkey_len1);
    EVP_PKEY *rsa_pubkey1 = PEM_read_bio_PUBKEY(bio_mem, NULL, NULL, NULL);

    BIO_free(bio_mem);

    bio_mem = BIO_new_mem_buf((void *) rsa_pubkey_bytes2, rsa_pubkey_len2);
    EVP_PKEY *rsa_pubkey2 = PEM_read_bio_PUBKEY(bio_mem, NULL, NULL, NULL);

    BIO_free(bio_mem);

    bio_mem = BIO_new_mem_buf((void *) rsa_pubkey_bytes3, rsa_pubkey_len3);
    EVP_PKEY *rsa_pubkey3 = PEM_read_bio_PUBKEY(bio_mem, NULL, NULL, NULL);

    BIO_free(bio_mem);

    bio_mem = BIO_new_mem_buf((void *) ecdsa_pubkey_bytes1, ecdsa_pubkey_len1);
    EVP_PKEY *ec_pubkey1 = PEM_read_bio_PUBKEY(bio_mem, NULL, NULL, NULL);

    BIO_free(bio_mem);

    bio_mem = BIO_new_mem_buf((void *) ecdsa_pubkey_bytes2, ecdsa_pubkey_len2);
    EVP_PKEY *ec_pubkey2 = PEM_read_bio_PUBKEY(bio_mem, NULL, NULL, NULL);

    BIO_free(bio_mem);

    bio_mem = BIO_new_mem_buf((void *) ecdsa_pubkey_bytes3, ecdsa_pubkey_len3);
    EVP_PKEY *ec_pubkey3 = PEM_read_bio_PUBKEY(bio_mem, NULL, NULL, NULL);

    BIO_free(bio_mem);

    ck_assert(rsa_pubkey1 != NULL);
    ck_assert(rsa_pubkey2 != NULL);
    ck_assert(rsa_pubkey3 != NULL);
    ck_assert(ec_pubkey1 != NULL);
    ck_assert(ec_pubkey2 != NULL);
    ck_assert(ec_pubkey3 != NULL);

    ck_assert(!cryptoutil_PublicKeyEqual(rsa_pubkey1, rsa_pubkey2));
    ck_assert(!cryptoutil_PublicKeyEqual(rsa_pubkey1, rsa_pubkey3));
    ck_assert(!cryptoutil_PublicKeyEqual(rsa_pubkey2, rsa_pubkey3));

    ck_assert(!cryptoutil_PublicKeyEqual(ec_pubkey1, ec_pubkey2));
    ck_assert(!cryptoutil_PublicKeyEqual(ec_pubkey1, ec_pubkey3));
    ck_assert(!cryptoutil_PublicKeyEqual(ec_pubkey2, ec_pubkey3));

    ck_assert(!cryptoutil_PublicKeyEqual(rsa_pubkey1, ec_pubkey1));
    ck_assert(!cryptoutil_PublicKeyEqual(rsa_pubkey1, ec_pubkey2));
    ck_assert(!cryptoutil_PublicKeyEqual(rsa_pubkey1, ec_pubkey3));

    ck_assert(!cryptoutil_PublicKeyEqual(rsa_pubkey2, ec_pubkey1));
    ck_assert(!cryptoutil_PublicKeyEqual(rsa_pubkey2, ec_pubkey2));
    ck_assert(!cryptoutil_PublicKeyEqual(rsa_pubkey2, ec_pubkey3));

    ck_assert(!cryptoutil_PublicKeyEqual(rsa_pubkey3, ec_pubkey1));
    ck_assert(!cryptoutil_PublicKeyEqual(rsa_pubkey3, ec_pubkey2));
    ck_assert(!cryptoutil_PublicKeyEqual(rsa_pubkey3, ec_pubkey3));

    ck_assert(cryptoutil_PublicKeyEqual(rsa_pubkey1, rsa_pubkey1));
    ck_assert(cryptoutil_PublicKeyEqual(rsa_pubkey2, rsa_pubkey2));
    ck_assert(cryptoutil_PublicKeyEqual(rsa_pubkey3, rsa_pubkey3));

    ck_assert(cryptoutil_PublicKeyEqual(ec_pubkey1, ec_pubkey1));
    ck_assert(cryptoutil_PublicKeyEqual(ec_pubkey2, ec_pubkey2));
    ck_assert(cryptoutil_PublicKeyEqual(ec_pubkey3, ec_pubkey3));

    EVP_PKEY_free(rsa_pubkey1);
    EVP_PKEY_free(rsa_pubkey2);
    EVP_PKEY_free(rsa_pubkey3);

    EVP_PKEY_free(ec_pubkey1);
    EVP_PKEY_free(ec_pubkey2);
    EVP_PKEY_free(ec_pubkey3);
}
END_TEST

Suite *keys_suite(void)
{
    Suite *s = suite_create("keys");
    TCase *tc_core = tcase_create("core");

    suite_add_tcase(s, tc_core);

    tcase_add_test(tc_core, test_cryptoutil_RSAPublicKeyEqual);
    tcase_add_test(tc_core, test_cryptoutil_ECDSAPublicKeyEqual);
    tcase_add_test(tc_core, test_cryptoutil_PublicKeyEqual);

    return s;
}

int main(void)
{
    Suite *s = keys_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
