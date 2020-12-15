#include <check.h>
#include "../src/id.h"

START_TEST(test_join)
{
    string_arr_t str_arr = NULL;
    arrput(str_arr, string_new("seg1"));
    arrput(str_arr, string_new("segment2"));
    arrput(str_arr, string_new("s3"));

    string_t res = join(str_arr);
    ck_assert_str_eq(res, "seg1/segment2/s3");

    util_string_arr_t_Free(str_arr);
    util_string_t_Free(res);
}
END_TEST

START_TEST(test_spiffeid_ID_New)
{
    
}
END_TEST

Suite* util_suite(void)
{
    Suite *s = suite_create("id");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_join);

    suite_add_tcase(s, tc_core);

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