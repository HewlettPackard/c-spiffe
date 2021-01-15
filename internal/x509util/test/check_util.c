#include <openssl/pem.h>
#include <check.h>
#include "../src/util.h"

START_TEST(test_x509util_CopyX509Authorities)
{
    const int ITERS = 4;

    FILE *f = fopen("certs.pem", "r");
    string_t buffer = FILE_to_string(f);
    fclose(f);

    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, buffer);
    arrfree(buffer);

    X509 **certs = NULL;
    for(int i = 0; i < ITERS; ++i)
    {
        //load certificate here
        X509 *cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
        if(cert)
            arrput(certs, cert);
    }

    X509 **certs_copy = x509util_CopyX509Authorities(certs);

    ck_assert_uint_eq(arrlenu(certs), ITERS);
    ck_assert_uint_eq(arrlenu(certs), arrlenu(certs_copy));
    for(size_t i = 0, size = arrlenu(certs); i < size; ++i)
    {
        ck_assert_int_eq(X509_cmp(certs[i], certs_copy[i]), 0);

        X509_free(certs[i]);
        X509_free(certs_copy[i]);
    }

    arrfree(certs);
    arrfree(certs_copy);
}
END_TEST

START_TEST(test_x509util_CertsEqual)
{
    const int ITERS = 4;

    FILE *f = fopen("certs.pem", "r");
    string_t buffer = FILE_to_string(f);
    fclose(f);

    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, buffer);
    arrfree(buffer);

    X509 **certs1 = NULL, **certs2 = NULL;

    for(int i = 0; i < ITERS; ++i)
    {
        //load certificate here
        //dummy
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

    FILE *f = fopen("certs.pem", "r");
    string_t buffer = FILE_to_string(f);
    fclose(f);

    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, buffer);
    arrfree(buffer);

    X509 **certs = NULL;
    for(int i = 0; i < ITERS; ++i)
    {
        //load certificate here
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

Suite* util_suite(void)
{
    Suite *s = suite_create("util");
    TCase *tc_core = tcase_create("core");

    suite_add_tcase(s, tc_core);

    tcase_add_test(tc_core, test_x509util_CopyX509Authorities);
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