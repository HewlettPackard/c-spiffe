#include <openssl/pem.h>
#include <check.h>
#include "../src/verify.h"

START_TEST(test_x509svid_ParseAndVerify)
{

}
END_TEST
        
START_TEST(test_x509svid_Verify)
{

}
END_TEST
        
START_TEST(test_x509svid_IDFromCert)
{
    FILE *f = fopen("good-leaf-only.pem", "r");
    string_t buffer = FILE_to_string(f);
    fclose(f);

    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, buffer);
    arrfree(buffer);

    X509 *cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);

    ck_assert(cert != NULL);

    err_t err;
    spiffeid_ID id = x509svid_IDFromCert(cert, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert(id.td.name != NULL);
    ck_assert(id.path != NULL);
    ck_assert_str_eq(id.td.name, "example.org");
    ck_assert_str_eq(id.path, "/workload-1");

    BIO_free(bio_mem);
    X509_free(cert);
    spiffeid_ID_Free(&id, false);
}
END_TEST

Suite* verify_suite(void)
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