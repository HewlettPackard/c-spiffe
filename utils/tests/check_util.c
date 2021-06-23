#include "c-spiffe/utils/util.h"
#include <check.h>
#include <stdlib.h>

START_TEST(test_string_new)
{
    const char res_str[] = "abcd";
    string_t str1 = string_new(res_str);
    string_t str2 = string_new(str1);

    ck_assert_str_eq(str1, res_str);
    ck_assert_uint_eq(arrlenu(str1), sizeof res_str);

    ck_assert_str_eq(str2, res_str);
    ck_assert_uint_eq(arrlenu(str2), sizeof res_str);

    arrfree(str1);
    arrfree(str2);
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
    ck_assert_uint_eq(arrlenu(str1), sizeof res_str);

    arrfree(str1);
    arrfree(str2);
    arrfree(str3);
}
END_TEST

START_TEST(test_string_new_range)
{
    const char test_str[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "abcdefghijklmnopqrstuvwxyz"
                            "0123456789";

    string_t str1 = string_new_range(test_str, test_str + 10);
    string_t str2 = string_new_range(test_str + 26, test_str + 36);
    string_t str3 = string_new_range(test_str + 52, test_str + 62);

    ck_assert_str_eq(str1, "ABCDEFGHIJ");
    ck_assert_str_eq(str2, "abcdefghij");
    ck_assert_str_eq(str3, "0123456789");

    arrfree(str1);
    arrfree(str2);
    arrfree(str3);
}
END_TEST

START_TEST(test_FILE_to_string)
{
    FILE *f = fopen("./resources/test.txt", "r");
    string_t buffer = FILE_to_string(f);
    fclose(f);

    ck_assert_ptr_ne(buffer, NULL);
    ck_assert_uint_ge(arrlenu(buffer), 63);
    ck_assert_str_eq(buffer, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                             "abcdefghijklmnopqrstuvwxyz"
                             "0123456789");

    arrfree(buffer);
}
END_TEST

Suite *util_suite(void)
{
    Suite *s = suite_create("util");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_string_new);
    tcase_add_test(tc_core, test_string_push);
    tcase_add_test(tc_core, test_string_new_range);
    tcase_add_test(tc_core, test_FILE_to_string);

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
