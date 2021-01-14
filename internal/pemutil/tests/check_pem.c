#include <check.h>
#include "../src/pem.h"

START_TEST(test_pemutil_ParseCertificates)
{
    //dummy
    ck_assert(0==1);
}
END_TEST

START_TEST(test_pemutil_ParsePrivateKey)
{
    //dummy
    ck_assert(0==1);
}
END_TEST

START_TEST(test_pemutil_EncodeCertificates)
{
    //dummy
    ck_assert(0==1);
}
END_TEST

START_TEST(test_pemutil_EncodePrivateKey)
{
    //dummy
    ck_assert(0==1);
}
END_TEST

Suite* pem_suite(void)
{
    Suite *s = suite_create("pem");
    TCase *tc_core = tcase_create("core");

    suite_add_tcase(s, tc_core);

    tcase_add_test(tc_core, test_pemutil_ParseCertificates);
    tcase_add_test(tc_core, test_pemutil_ParsePrivateKey);
    tcase_add_test(tc_core, test_pemutil_EncodeCertificates);
    tcase_add_test(tc_core, test_pemutil_EncodePrivateKey);

    return s;
}

int main(void)
{
    Suite *s = pem_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);
    
    srunner_free(sr);
    
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}