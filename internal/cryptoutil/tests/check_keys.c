#include <check.h>
#include "../src/keys.h"

START_TEST(test_cryptoutil_RSAPublicKeyEqual)
{
    //dummy
    ck_assert(0==1);
}
END_TEST

START_TEST(test_cryptoutil_ECDSAPublicKeyEqual)
{
    //dummy
    ck_assert(0==1);
}
END_TEST

START_TEST(test_cryptoutil_PublicKeyEqual)
{
    //dummy
    ck_assert(0==1);
}
END_TEST

Suite* keys_suite(void)
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