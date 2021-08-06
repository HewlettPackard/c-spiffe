#include "c-spiffe/svid/x509svid/verify.h"
#include <check.h>
#include <openssl/pem.h>

Suite *verify_suite(void)
{
    Suite *s = suite_create("verify");
    TCase *tc_core = tcase_create("core");

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
