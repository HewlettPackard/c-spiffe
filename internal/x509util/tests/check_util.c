#include "c-spiffe/internal/x509util/util.h"
#include <check.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

START_TEST(test_x509util_CopyX509Authorities)
{
    const int ITERS = 4;

    FILE *f = fopen("./resources/certs.pem", "r");
    string_t buffer = FILE_to_string(f);
    fclose(f);

    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, buffer);
    arrfree(buffer);

    X509 **certs = NULL;
    for(int i = 0; i < ITERS; ++i) {
        // load certificate here
        X509 *cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
        if(cert)
            arrput(certs, cert);
    }

    X509 **certs_copy = x509util_CopyX509Authorities(certs);

    ck_assert_uint_eq(arrlenu(certs), ITERS);
    ck_assert_uint_eq(arrlenu(certs), arrlenu(certs_copy));
    for(size_t i = 0, size = arrlenu(certs); i < size; ++i) {
        ck_assert_int_eq(X509_cmp(certs[i], certs_copy[i]), 0);

        X509_free(certs[i]);
        X509_free(certs_copy[i]);
    }

    BIO_free(bio_mem);
    arrfree(certs);
    arrfree(certs_copy);
}
END_TEST

START_TEST(test_x509util_ParseCertificates)
{
    const int ITERS = 4;

    FILE *f = fopen("./resources/certs.pem", "r");
    string_t buffer = FILE_to_string(f);
    fclose(f);

    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, buffer);
    arrfree(buffer);

    unsigned char der_bytes[10000];
    unsigned char *pout = der_bytes;

    X509 **certs = NULL;
    for(int i = 0; i < ITERS; ++i) {
        X509 *cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
        if(cert) {
            i2d_X509(cert, &pout);
            arrput(certs, cert);
        }
    }

    err_t err;
    X509 **parsed_certs
        = x509util_ParseCertificates(der_bytes, pout - der_bytes, &err);
    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_uint_eq(arrlenu(certs), arrlenu(parsed_certs));

    for(size_t i = 0, size = arrlenu(certs); i < size; ++i) {
        ck_assert_int_eq(X509_cmp(certs[i], parsed_certs[i]), 0);

        X509_free(certs[i]);
        X509_free(parsed_certs[i]);
    }

    BIO_free(bio_mem);
    arrfree(certs);
    arrfree(parsed_certs);
}
END_TEST

START_TEST(test_x509util_ParsePrivateKey)
{
    FILE *f = fopen("./resources/key-pkcs8-rsa.pem", "r");
    string_t buffer = FILE_to_string(f);
    fclose(f);

    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, buffer);
    arrfree(buffer);

    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio_mem, NULL, NULL, NULL);
    ck_assert_ptr_ne(pkey, NULL);

    unsigned char der_bytes[10000];
    unsigned char *pout = der_bytes;

    i2d_PrivateKey(pkey, &pout);

    err_t err;
    EVP_PKEY *parsed_pkey
        = x509util_ParsePrivateKey(der_bytes, pout - der_bytes, &err);
    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(parsed_pkey, NULL);

    RSA *rsa1 = EVP_PKEY_get0_RSA(pkey);
    RSA *rsa2 = EVP_PKEY_get0_RSA(parsed_pkey);

    const BIGNUM *p1 = NULL, *q1 = NULL, *d1 = NULL;
    RSA_get0_factors(rsa1, &p1, &q1);
    RSA_get0_key(rsa1, NULL, NULL, &d1);

    const BIGNUM *p2 = NULL, *q2 = NULL, *d2 = NULL;
    RSA_get0_factors(rsa2, &p2, &q2);
    RSA_get0_key(rsa1, NULL, NULL, &d2);

    ck_assert_int_eq(BN_cmp(p1, p2), 0);
    ck_assert_int_eq(BN_cmp(q1, q2), 0);
    ck_assert_int_eq(BN_cmp(d1, d2), 0);

    BIO_free(bio_mem);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(parsed_pkey);
}
END_TEST

START_TEST(test_x509util_CertsEqual)
{
    const int ITERS = 4;

    FILE *f = fopen("./resources/certs.pem", "r");
    string_t buffer = FILE_to_string(f);
    fclose(f);

    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, buffer);
    arrfree(buffer);

    X509 **certs1 = NULL, **certs2 = NULL;

    for(int i = 0; i < ITERS; ++i) {
        // load certificate here
        X509 *cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);

        arrput(certs1, cert);
        arrput(certs2, cert);
    }

    ck_assert(x509util_CertsEqual(certs1, certs2));

    arrpop(certs1);
    ck_assert(!x509util_CertsEqual(certs1, certs2));

    arrpop(certs2);
    ck_assert(x509util_CertsEqual(certs1, certs2));

    arrdel(certs1, 0);
    ck_assert(!x509util_CertsEqual(certs1, certs2));

    X509 *temp_cert = arrpop(certs1);
    arrins(certs1, 0, temp_cert);
    arrdelswap(certs2, 0);
    ck_assert(x509util_CertsEqual(certs1, certs2));

    arrfree(certs1);
    arrfree(certs2);
    ck_assert(x509util_CertsEqual(certs1, certs2));

    BIO_free(bio_mem);
}
END_TEST

START_TEST(test_x509util_NewCertPool)
{
    const int ITERS = 4;

    FILE *f = fopen("./resources/certs.pem", "r");
    string_t buffer = FILE_to_string(f);
    fclose(f);

    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, buffer);
    arrfree(buffer);

    X509 **certs = NULL;
    for(int i = 0; i < ITERS; ++i) {
        // load certificate here
        X509 *cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
        if(cert)
            arrput(certs, cert);
    }

    x509util_CertPool *certpool = x509util_NewCertPool(certs);

    ck_assert_uint_eq(arrlenu(certpool->certs), 3);

    BIO_free(bio_mem);
    x509util_CertPool_Free(certpool);
}
END_TEST

Suite *util_suite(void)
{
    Suite *s = suite_create("util");
    TCase *tc_core = tcase_create("core");

    suite_add_tcase(s, tc_core);

    tcase_add_test(tc_core, test_x509util_CopyX509Authorities);
    tcase_add_test(tc_core, test_x509util_ParseCertificates);
    tcase_add_test(tc_core, test_x509util_ParsePrivateKey);
    tcase_add_test(tc_core, test_x509util_CertsEqual);
    tcase_add_test(tc_core, test_x509util_NewCertPool);

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
