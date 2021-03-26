#include "svid/x509svid/src/verify.h"
#include <check.h>
#include <openssl/pem.h>

START_TEST(test_x509svid_ParseAndVerify)
{
    /** first case */

    FILE *f = fopen("./resources/good-leaf-and-intermediate.pem", "r");
    ck_assert_ptr_ne(f, NULL);

    X509 *leaf = PEM_read_X509(f, NULL, NULL, NULL);
    X509 *inter = PEM_read_X509(f, NULL, NULL, NULL);
    ck_assert_ptr_ne(leaf, NULL);
    ck_assert_ptr_ne(inter, NULL);
    fclose(f);

    X509 **certs = NULL;
    arrput(certs, leaf);
    arrput(certs, inter);

    err_t err;
    byte **pem_certs = pemutil_EncodeCertificates(certs, &err);
    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(pem_certs, NULL);

    /// TODO: build bundle source

    spiffeid_ID id;
    X509 ***chains = x509svid_ParseAndVerify(pem_certs, NULL, &id, &err);

    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert_ptr_eq(chains, NULL);
    ck_assert_ptr_eq(id.td.name, NULL);
    ck_assert_ptr_eq(id.path, NULL);

    for(size_t i = 0, size = arrlenu(certs); i < size; ++i) {
        X509_free(certs[i]);
    }
    arrfree(certs);

    for(size_t i = 0, size = arrlenu(pem_certs); i < size; ++i) {
        arrfree(pem_certs[i]);
    }
    arrfree(pem_certs);
}
END_TEST

START_TEST(test_x509svid_Verify)
{
    /** first case */

    FILE *f = fopen("./resources/good-leaf-and-intermediate.pem", "r");
    ck_assert_ptr_ne(f, NULL);

    X509 *leaf = PEM_read_X509(f, NULL, NULL, NULL);
    X509 *inter = PEM_read_X509(f, NULL, NULL, NULL);
    ck_assert_ptr_ne(leaf, NULL);
    ck_assert_ptr_ne(inter, NULL);
    fclose(f);

    X509 **certs = NULL;
    arrput(certs, leaf);
    arrput(certs, inter);

    /// TODO: build bundle source

    spiffeid_ID id;
    err_t err;
    X509 ***chains = x509svid_Verify(certs, NULL, &id, &err);

    ck_assert_ptr_eq(chains, NULL);
    ck_assert_ptr_eq(id.td.name, NULL);
    ck_assert_ptr_eq(id.path, NULL);
    ck_assert_uint_ne(err, NO_ERROR);

    for(size_t i = 0, size = arrlenu(certs); i < size; ++i) {
        X509_free(certs[i]);
    }
    arrfree(certs);
}
END_TEST

START_TEST(test_x509svid_IDFromCert)
{
    /** first case */

    FILE *f = fopen("./resources/good-leaf-only.pem", "r");
    ck_assert_ptr_ne(f, NULL);

    X509 *cert = PEM_read_X509(f, NULL, NULL, NULL);
    ck_assert_ptr_ne(cert, NULL);
    fclose(f);

    err_t err;
    spiffeid_ID id = x509svid_IDFromCert(cert, &err);
    X509_free(cert);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(id.td.name, NULL);
    ck_assert_ptr_ne(id.path, NULL);
    ck_assert_str_eq(id.td.name, "example.org");
    ck_assert_str_eq(id.path, "/workload-1");

    spiffeid_ID_Free(&id);

    /** second case */

    f = fopen("./resources/wrong-leaf-empty-id.pem", "r");
    ck_assert_ptr_ne(f, NULL);

    cert = PEM_read_X509(f, NULL, NULL, NULL);
    ck_assert_ptr_ne(cert, NULL);
    fclose(f);

    id = x509svid_IDFromCert(cert, &err);
    X509_free(cert);

    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert_ptr_eq(id.td.name, NULL);
    ck_assert_ptr_eq(id.path, NULL);
}
END_TEST

Suite *verify_suite(void)
{
    Suite *s = suite_create("verify");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_x509svid_IDFromCert);
    tcase_add_test(tc_core, test_x509svid_Verify);
    tcase_add_test(tc_core, test_x509svid_ParseAndVerify);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    Suite *s = verify_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
