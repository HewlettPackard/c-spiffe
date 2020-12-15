#include <stdlib.h>
#include <check.h>
#include "../src/util.h"

START_TEST(test_string_new)
{
    string_t str1 = string_new("abcd");
    string_t str2 = string_new(str1);

    ck_assert_str_eq(str1, "abcd");
    ck_assert_uint_ge(arrlenu(str1), 5);

    ck_assert_str_eq(str2, "abcd");
    ck_assert_uint_ge(arrlenu(str2), 5);
}
END_TEST

START_TEST(test_string_push)
{
    string_t str1 = string_new("olar, querida.");
    string_t str2 = string_new(" como vai?");
    string_t str3 = string_new(" ;)\n");
    const char res_str[] = "olar, querida. como vai? ;)\n";

    str1 = string_push(str1, str2);
    str1 = string_push(str1, str3);

    ck_assert_str_eq(str1, res_str);
    ck_assert_uint_ge(arrlenu(str1), sizeof res_str);
}
END_TEST

Suite* util_suite(void)
{
    Suite *s = suite_create("util");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_string_new);
    tcase_add_test(tc_core, test_string_push);

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