#include "../../svid/jwtsvid/src/svid.h"
#include "../src/jwtsource.h"
#include "../src/jwtwatcher.h"
#include <check.h>

START_TEST(test_workloadapi_NewJWTSource_creates_default_config);
{
    err_t err;
    workloadapi_JWTSource *tested = workloadapi_NewJWTSource(NULL, &err);

    ck_assert_int_eq(err, NO_ERROR);
    ck_assert(tested->closed);

    ck_assert_ptr_ne(tested->config, NULL);
    ck_assert_ptr_ne(tested->watcher, NULL);
    ck_assert_ptr_ne(tested->watcher->client, NULL);
    ck_assert_ptr_ne(tested->config->watcher_config.client_options, NULL);
    ck_assert_ptr_eq(tested->config->watcher_config.client_options[0],
                     workloadapi_Client_defaultOptions);

    ck_assert_ptr_eq(tested->bundles, NULL);

    ck_assert_ptr_eq(tested->watcher->jwt_callback.args, tested);

    workloadapi_JWTSource_Free(tested);
}
END_TEST

// jwtsvid_SVID *custom_picker(jwtsvid_SVID **svids) { return svids[1]; }

void custom_option(workloadapi_Client *client, void *not_used)
{
    workloadapi_Client_SetAddress(client, "unix:///var/example_agent");
}

START_TEST(test_workloadapi_NewJWTSource_uses_config);
{
    err_t err = NO_ERROR;

    workloadapi_JWTSourceConfig config;
    config.watcher_config.client_options = NULL;
    arrpush(config.watcher_config.client_options, custom_option);
    config.watcher_config.client = NULL;

    workloadapi_JWTSource *tested = workloadapi_NewJWTSource(&config, &err);

    ck_assert_int_eq(err, NO_ERROR);
    ck_assert_ptr_eq(tested->config, &config);
    ck_assert_ptr_ne(tested->watcher, NULL);
    ck_assert_str_eq(tested->watcher->client->address,
                     "unix:///var/example_agent");
    ck_assert(tested->closed);

    ck_assert_ptr_eq(tested->bundles, NULL);
    workloadapi_JWTSource_Free(tested);
}
END_TEST

START_TEST(test_workloadapi_JWTSource_applyJWTBundle_Set);
{
    err_t err;
    workloadapi_JWTSource *tested = workloadapi_NewJWTSource(NULL, &err);

    jwtbundle_Set *set = (jwtbundle_Set *) 1;

    workloadapi_JWTSource_applyJWTBundle_Set(tested, set);

    ck_assert_ptr_eq(tested->bundles, (jwtbundle_Set *) 1);

    tested->bundles = NULL;
    workloadapi_JWTSource_Free(tested);
}
END_TEST

int waitAndUpdate(void *args)
{
    struct timespec now = { 3, 0 };
    thrd_sleep(&now, NULL);
    ck_assert(!((workloadapi_JWTSource *) args)->closed);
    workloadapi_JWTWatcher_TriggerUpdated(
        ((workloadapi_JWTSource *) args)->watcher);
    return 0;
}

START_TEST(test_workloadapi_JWTSource_Start_waits_and_sets_closed_false);
{
    err_t err;
    workloadapi_JWTSource *tested = workloadapi_NewJWTSource(NULL, &err);
    struct timespec then;
    timespec_get(&then, TIME_UTC);
    thrd_t thread;
    thrd_create(&thread, waitAndUpdate, tested);

    workloadapi_JWTSource_Start(tested);

    struct timespec now;
    timespec_get(&now, TIME_UTC);

    ck_assert_int_ge(now.tv_sec, then.tv_sec + 2);
    ck_assert_int_lt(now.tv_sec, then.tv_sec + 5);

    ck_assert_int_eq(workloadapi_JWTSource_checkClosed(tested), NO_ERROR);

    workloadapi_JWTSource_Close(tested);

    tested->bundles = NULL;
    workloadapi_JWTSource_Free(tested);
}
END_TEST

START_TEST(test_workloadapi_JWTSource_Closes_watcher);
{
    err_t err;
    workloadapi_JWTSource *tested = workloadapi_NewJWTSource(NULL, &err);
    struct timespec then;
    timespec_get(&then, TIME_UTC);
    thrd_t thread;
    thrd_create(&thread, waitAndUpdate, tested);

    workloadapi_JWTSource_Start(tested);

    struct timespec now;
    timespec_get(&now, TIME_UTC);

    ck_assert_int_ge(now.tv_sec, then.tv_sec + 2);
    ck_assert_int_lt(now.tv_sec, then.tv_sec + 5);

    ck_assert_int_eq(workloadapi_JWTSource_checkClosed(tested), NO_ERROR);
    ck_assert(!tested->watcher->closed);

    workloadapi_JWTSource_Close(tested);

    ck_assert_int_eq(workloadapi_JWTSource_checkClosed(tested), ERROR1);
    ck_assert(tested->watcher->closed);

    tested->bundles = NULL;
    workloadapi_JWTSource_Free(tested);
}
END_TEST

Suite *watcher_suite(void)
{
    Suite *s = suite_create("jwtsource");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core,
                   test_workloadapi_NewJWTSource_creates_default_config);
    tcase_add_test(tc_core, test_workloadapi_NewJWTSource_uses_config);
    tcase_add_test(tc_core, test_workloadapi_JWTSource_applyJWTBundle_Set);
    tcase_add_test(
        tc_core, test_workloadapi_JWTSource_Start_waits_and_sets_closed_false);
    tcase_add_test(tc_core, test_workloadapi_JWTSource_Closes_watcher);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(int argc, char **argv)
{
    Suite *s = watcher_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
