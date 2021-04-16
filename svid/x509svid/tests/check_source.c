#include "svid/x509svid/src/source.h"
#include <check.h>

START_TEST(test_x509svid_SourceFromSource)
{
    /* type puning from integer '1' to address 0x1, which is a placeholder for
     * the actual pointer. */
    x509svid_Source *source
        = x509svid_SourceFromSource((workloadapi_X509Source *) 0x1);

    ck_assert_ptr_ne(source, NULL);

    x509svid_Source_Free(source);
}
END_TEST

Suite *source_suite(void)
{
    Suite *s = suite_create("source");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_x509svid_SourceFromSource);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    Suite *s = source_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
