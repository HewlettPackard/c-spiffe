#include "internal/x509util/src/certpool.h"
#include <check.h>
#include <openssl/pem.h>

START_TEST(test_x509util_CertPool_New)
{
    x509util_CertPool *cp = x509util_CertPool_New();

    ck_assert(cp->certs == NULL);
    ck_assert(cp->name_idcs == NULL);
    ck_assert(cp->subj_keyid_idcs == NULL);

    x509util_CertPool_Free(cp);
}
END_TEST

START_TEST(test_x509util_CertPool_contains)
{
    const int ITERS = 4;

    FILE *f = fopen("./resources/certs.pem", "r");
    string_t buffer = FILE_to_string(f);
    fclose(f);

    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, buffer);
    arrfree(buffer);

    x509util_CertPool *cp = x509util_CertPool_New();

    X509 **certs = NULL;
    for(int i = 0; i < ITERS; ++i) {
        // load certificate here
        X509 *cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
        if(cert) {
            arrput(certs, cert);
        }
    }

    for(size_t i = 0, size = arrlenu(certs); i < size; ++i) {
        ck_assert(!x509util_CertPool_contains(cp, certs[i]));
    }

    for(size_t i = 0, size = arrlenu(certs); i < size; ++i) {
        x509util_CertPool_AddCert(cp, certs[i]);
    }

    for(size_t i = 0, size = arrlenu(certs); i < size; ++i) {
        ck_assert(x509util_CertPool_contains(cp, certs[i]));
    }

    for(size_t i = 0, size = arrlenu(certs); i < size; ++i) {
        X509_free(certs[i]);
    }
    arrfree(certs);

    BIO_free(bio_mem);
    x509util_CertPool_Free(cp);
}
END_TEST

Suite *certpool_suite(void)
{
    Suite *s = suite_create("certpool");
    TCase *tc_core = tcase_create("core");

    suite_add_tcase(s, tc_core);

    tcase_add_test(tc_core, test_x509util_CertPool_New);
    tcase_add_test(tc_core, test_x509util_CertPool_contains);

    return s;
}

int main(void)
{
    Suite *s = certpool_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
