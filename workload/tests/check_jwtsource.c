#include "c-spiffe/svid/jwtsvid/svid.h"
#include "c-spiffe/workload/jwtsource.h"
#include "c-spiffe/workload/jwtwatcher.h"
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

    workloadapi_JWTSourceConfig *config = calloc(1, sizeof(*config));
    config->watcher_config.client_options = NULL;
    arrpush(config->watcher_config.client_options, custom_option);
    config->watcher_config.client = NULL;

    workloadapi_JWTSource *tested = workloadapi_NewJWTSource(config, &err);

    ck_assert_int_eq(err, NO_ERROR);
    ck_assert_ptr_eq(tested->config, config);
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

    jwtbundle_Set *set = jwtbundle_NewSet(0);
    spiffeid_TrustDomain td
        = spiffeid_TrustDomainFromString("spiffe://example.com", &err);
    jwtbundle_Bundle *bundle = jwtbundle_New(td);
    jwtbundle_Set_Add(set, bundle);
    workloadapi_JWTSource_applyJWTBundle_Set(tested, set);

    ck_assert_ptr_ne(tested->bundles, set);
    ck_assert_str_eq(tested->bundles->bundles[0].value->td.name,
                     set->bundles[0].value->td.name);

    tested->bundles = NULL;
    workloadapi_JWTSource_Free(tested);
    spiffeid_TrustDomain_Free(&td);
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

    ck_assert_int_eq(workloadapi_JWTSource_checkClosed(tested), ERR_CLOSED);
    ck_assert(tested->watcher->closed);

    tested->bundles = NULL;
    workloadapi_JWTSource_Free(tested);
}
END_TEST

START_TEST(test_workloadapi_JWTSource_GetJWTSVID_fails_if_closed);
{
    err_t err;
    workloadapi_JWTSource *tested = workloadapi_NewJWTSource(NULL, &err);
    jwtsvid_SVID *svid = workloadapi_JWTSource_GetJWTSVID(tested, NULL, &err);

    ck_assert_ptr_eq(svid, NULL);
    ck_assert_int_eq(err, ERR_CLOSED);

    workloadapi_JWTSource_Free(tested);
}
END_TEST

START_TEST(test_workloadapi_JWTSource_GetJWTBundleForTrustDomain);
{
    err_t err;
    workloadapi_JWTSource *tested = workloadapi_NewJWTSource(NULL, &err);
    string_t td_url = string_new("example.org");
    spiffeid_TrustDomain td = spiffeid_TrustDomainFromString(td_url, &err);

    jwtbundle_Bundle *bundle
        = workloadapi_JWTSource_GetJWTBundleForTrustDomain(tested, td, &err);

    ck_assert_ptr_eq(bundle, NULL);
    ck_assert_int_eq(err, ERR_CLOSED); // source closed

    tested->closed = false;
    tested->bundles = jwtbundle_NewSet(0);
    bundle
        = workloadapi_JWTSource_GetJWTBundleForTrustDomain(tested, td, &err);

    ck_assert_ptr_eq(bundle, NULL);
    ck_assert_int_eq(err, ERR_INVALID_TRUSTDOMAIN); // trust domain not available

    jwtbundle_Set_Free(tested->bundles);
    tested->bundles = NULL;
    tested->closed = true;
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
    tcase_add_test(tc_core,
                   test_workloadapi_JWTSource_GetJWTSVID_fails_if_closed);
    tcase_add_test(tc_core,
                   test_workloadapi_JWTSource_GetJWTBundleForTrustDomain);

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
