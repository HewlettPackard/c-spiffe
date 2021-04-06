#include "spiffetls/tlsconfig/src/config.h"
#include <check.h>

void option_dummy(tlsconfig_options *opt)
{
    if(opt) {
        opt->trace = (void *) 0x1;
    }
}

void option_dummy2(tlsconfig_options *opt)
{
    if(opt) {
        opt->trace = ((uint64_t) opt->trace) + 1;
    }
}

START_TEST(test_tlsconfig_Option_apply)
{
    tlsconfig_Option *op = tlsconfig_OptionFromFunc(option_dummy);
    tlsconfig_options opt;
    tlsconfig_Option_apply(op, &opt);

    ck_assert_ptr_eq(opt.trace, (void *) 0x1);

    tlsconfig_Option_Free(op);
}
END_TEST

START_TEST(test_tlsconfig_OptionFromFunc)
{
    tlsconfig_Option *op = tlsconfig_OptionFromFunc(option_dummy);
    
    ck_assert_uint_eq(op->type, TLSCONFIG_FUNC);
    ck_assert_ptr_eq(op->source.func, option_dummy);

    tlsconfig_Option_Free(op);
}
END_TEST

START_TEST(test_tlsconfig_newOptions)
{
    tlsconfig_Option *opt1 = tlsconfig_OptionFromFunc(option_dummy);
    tlsconfig_Option *opt2 = tlsconfig_OptionFromFunc(option_dummy2);
    tlsconfig_Option **opts = NULL;
    arrput(opts, opt1);
    arrput(opts, opt2);
    tlsconfig_options *op = tlsconfig_newOptions(opts);
    
    ck_assert_ptr_eq(op->trace, (void*) 0x9);

    for(size_t i = 0, size = arrlenu(opts); i < size; ++i) {
        tlsconfig_Option_Free(opts[i]);
    }
    arrfree(opts);
    free(op);
}
END_TEST

START_TEST(test_tlsconfig_HookTLSClientConfig)
{

}
END_TEST

START_TEST(test_tlsconfig_HookMTLSClientConfig)
{

}
END_TEST

START_TEST(test_tlsconfig_resetAuthFields)
{

}
END_TEST

Suite *config_suite(void)
{
    Suite *s = suite_create("config");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_tlsconfig_Option_apply);
    tcase_add_test(tc_core, test_tlsconfig_newOptions);
    tcase_add_test(tc_core, test_tlsconfig_HookTLSClientConfig);
    tcase_add_test(tc_core, test_tlsconfig_HookMTLSClientConfig);
    tcase_add_test(tc_core, test_tlsconfig_resetAuthFields);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    Suite *s = config_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
