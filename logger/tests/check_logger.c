#include "logger/logger.h"

#include <check.h>

START_TEST(test_logger_Debug_FmtPush)
{
    logger_Init();

    char buff[64];
    for(int i = 0; i < 1000; ++i) {
        sprintf(buff, "Log %d", i);
        logger_Debug_FmtPush("Log %d", i);

        ck_assert_ptr_ne(strstr(logger_Debug_Back(), buff), NULL);
    }

    logger_Cleanup();
}
END_TEST

START_TEST(test_logger_Debug_Push)
{
    logger_Init();

    char buff[64];
    for(int i = 0; i < 1000; ++i) {
        sprintf(buff, "Log %d", i);
        logger_Debug_Push(buff);

        ck_assert_ptr_ne(strstr(logger_Debug_Back(), buff), NULL);
    }

    logger_Cleanup();
}
END_TEST

START_TEST(test_logger_Debug_Pop)
{
    logger_Init();

    const int ITERS = 10;
    for(int i = 0; i < ITERS; ++i) {
        logger_Debug_FmtPush("Log %d", i);
    }

    for(int i = 0; i < ITERS; ++i) {
        const char *msg = logger_Debug_Back();
        ck_assert_ptr_ne(msg, NULL);
        logger_Debug_Pop();
    }
    ck_assert_ptr_eq(logger_Debug_Back(), NULL);

    logger_Cleanup();
}
END_TEST

START_TEST(test_logger_Debug_Dumps)
{
    logger_Init();

    const int ITERS = 64;
    for(int i = 0; i < 64; ++i) {
        logger_Debug_FmtPush("Log %d", i);
    }
    string_t logs_str = logger_Debug_Dumps();

    char buff[64];
    for(int i = 0; i < 64; ++i) {
        sprintf(buff, "Log %d\n", i);
        ck_assert_ptr_ne(strstr(logs_str, buff), NULL);
    }

    arrfree(logs_str);
    logger_Cleanup();
}
END_TEST

START_TEST(test_logger_Debug_Dumpf)
{
    logger_Init();

    const int ITERS = 64;
    for(int i = 0; i < 64; ++i) {
        logger_Debug_FmtPush("Log %d", i);
    }

    string_t filename = string_new(tmpnam(NULL));
    FILE *f = fopen(filename, "w+");
    logger_Debug_Dumpf(f);

    rewind(f);

    /// TODO: check for messages

    fclose(f);
    remove(filename);
    arrfree(filename);
    logger_Cleanup();
}
END_TEST

Suite *logger_suite(void)
{
    Suite *s = suite_create("logger");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_logger_Debug_FmtPush);
    tcase_add_test(tc_core, test_logger_Debug_Push);
    tcase_add_test(tc_core, test_logger_Debug_Pop);
    tcase_add_test(tc_core, test_logger_Debug_Dumps);
    tcase_add_test(tc_core, test_logger_Debug_Dumpf);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    Suite *s = logger_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
