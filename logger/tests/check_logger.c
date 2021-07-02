#include "c-spiffe/logger/logger.h"

#include <check.h>

START_TEST(test_logger_FmtPush)
{
    logger_InitAll();

    char buff[64];
    for(int i = 0; i < 1000; ++i) {
        sprintf(buff, "Log %d", i);
        logger_FmtPush(LOGGER_DEBUG, "Log %d", i);

        ck_assert_ptr_ne(strstr(logger_Back(LOGGER_DEBUG), buff), NULL);
    }

    logger_CleanupAll();
}
END_TEST

START_TEST(test_logger_Push)
{
    logger_InitAll();

    char buff[64];
    for(int i = 0; i < 1000; ++i) {
        sprintf(buff, "Log %d", i);
        logger_Push(LOGGER_DEBUG, buff);

        ck_assert_ptr_ne(strstr(logger_Back(LOGGER_DEBUG), buff), NULL);
    }

    logger_CleanupAll();
}
END_TEST

START_TEST(test_logger_Pop)
{
    logger_InitAll();

    const int SIZE = logger_BufferSize(LOGGER_DEBUG);
    const int ITERS = 3 * SIZE / 2;
    for(int i = 0; i < ITERS; ++i) {
        logger_FmtPush(LOGGER_DEBUG, "Log %d", i);
    }

    for(int i = 0; i < SIZE; ++i) {
        const char *msg = logger_Back(LOGGER_DEBUG);
        ck_assert_ptr_ne(msg, NULL);
        logger_Pop(LOGGER_DEBUG);
    }
    ck_assert_ptr_eq(logger_Back(LOGGER_DEBUG), NULL);

    logger_CleanupAll();
}
END_TEST

START_TEST(test_logger_Dumps)
{
    logger_InitAll();

    const int SIZE = logger_BufferSize(LOGGER_DEBUG);
    const int ITERS = 3 * SIZE / 2;
    for(int i = 0; i < ITERS; ++i) {
        logger_FmtPush(LOGGER_DEBUG, "Log %d", i);
    }
    string_t logs_str = logger_Dumps(LOGGER_DEBUG);

    char buff[64];
    for(int i = ITERS - SIZE; i < ITERS; ++i) {
        sprintf(buff, "Log %d\n", i);
        ck_assert_ptr_ne(strstr(logs_str, buff), NULL);
    }

    arrfree(logs_str);
    logger_CleanupAll();
}
END_TEST

START_TEST(test_logger_Dumpf)
{
    logger_InitAll();

    const int SIZE = logger_BufferSize(LOGGER_DEBUG);
    const int ITERS = 3 * SIZE / 2;
    for(int i = 0; i < ITERS; ++i) {
        logger_FmtPush(LOGGER_DEBUG, "Log %d", i);
    }

    string_t filename = string_new(tmpnam(NULL));
    FILE *f = fopen(filename, "w+");
    logger_Dumpf(LOGGER_DEBUG, f);

    rewind(f);

    fclose(f);
    remove(filename);
    arrfree(filename);
    logger_CleanupAll();
}
END_TEST

Suite *logger_suite(void)
{
    Suite *s = suite_create("logger");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_logger_FmtPush);
    tcase_add_test(tc_core, test_logger_Push);
    tcase_add_test(tc_core, test_logger_Pop);
    tcase_add_test(tc_core, test_logger_Dumps);
    tcase_add_test(tc_core, test_logger_Dumpf);

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
