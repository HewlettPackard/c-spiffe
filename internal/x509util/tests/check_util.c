#include <check.h>
#include "../src/util.h"

START_TEST(test_x509util_CopyX509Authorities)
{
    //dummy
    ck_assert(0==1);
}
END_TEST

START_TEST(test_x509util_CertsEqual)
{
    //dummy
    ck_assert(0==1);
}
END_TEST

Suite* util_suite(void)
{
    Suite *s = suite_create("util");
    TCase *tc_core = tcase_create("core");

    suite_add_tcase(s, tc_core);

    tcase_add_test(tc_core, test_x509util_CopyX509Authorities);
    tcase_add_test(tc_core, test_x509util_CertsEqual);

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