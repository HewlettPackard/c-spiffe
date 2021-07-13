#include "c-spiffe/svid/x509svid/svid.h"
#include "c-spiffe/workload/watcher.h"
#include "c-spiffe/workload/x509source.h"
#include <check.h>

START_TEST(test_workloadapi_NewX509Source_creates_default_config);
{
    err_t err;
    workloadapi_X509Source *tested = workloadapi_NewX509Source(NULL, &err);

    ck_assert_int_eq(err, NO_ERROR);
    ck_assert(tested->closed);

    ck_assert_ptr_ne(tested->config, NULL);
    ck_assert_ptr_ne(tested->watcher, NULL);
    ck_assert_ptr_ne(tested->watcher->client, NULL);
    ck_assert_ptr_ne(tested->config->watcher_config.client_options, NULL);
    ck_assert_ptr_eq(tested->config->watcher_config.client_options[0],
                     workloadapi_Client_defaultOptions);
    ck_assert_ptr_eq(tested->config->picker, x509svid_SVID_GetDefaultX509SVID);

    ck_assert_ptr_eq(tested->svids, NULL);
    ck_assert_ptr_eq(tested->bundles, NULL);

    ck_assert_ptr_eq(tested->watcher->x509callback.args, tested);

    workloadapi_X509Source_Free(tested);
}
END_TEST

x509svid_SVID *custom_picker(x509svid_SVID **svids) { return svids[1]; }

void custom_option(workloadapi_Client *client, void *not_used)
{
    workloadapi_Client_SetAddress(client, "unix:///var/example_agent");
}

START_TEST(test_workloadapi_NewX509Source_uses_config);
{
    err_t err = NO_ERROR;

    workloadapi_X509SourceConfig config;
    config.picker = custom_picker;
    config.watcher_config.client_options = NULL;
    arrpush(config.watcher_config.client_options, custom_option);
    config.watcher_config.client = NULL;

    workloadapi_X509Source *tested = workloadapi_NewX509Source(&config, &err);

    ck_assert_int_eq(err, NO_ERROR);
    ck_assert_ptr_eq(tested->config, &config);
    ck_assert_ptr_eq(tested->config->picker, custom_picker);
    ck_assert_ptr_ne(tested->watcher, NULL);
    ck_assert_str_eq(tested->watcher->client->address,
                     "unix:///var/example_agent");
    ck_assert(tested->closed);

    ck_assert_ptr_eq(tested->svids, NULL);
    ck_assert_ptr_eq(tested->bundles, NULL);
    workloadapi_X509Source_Free(tested);
}
END_TEST

START_TEST(test_workloadapi_X509Source_GetX509SVID_default_picker);
{
    err_t err;
    workloadapi_X509SourceConfig config;
    config.picker = x509svid_SVID_GetDefaultX509SVID;
    config.watcher_config.client_options = NULL;
    config.watcher_config.client = NULL;

    workloadapi_X509Source *tested = workloadapi_NewX509Source(&config, &err);

    x509svid_SVID _svid1;
    x509svid_SVID _svid2;
    x509svid_SVID *svid1 = &_svid1;
    x509svid_SVID *svid2 = &_svid2;
    spiffeid_ID id1
        = spiffeid_FromString("spiffe://example.org/workload1", &err);
    spiffeid_ID id2
        = spiffeid_FromString("spiffe://example.org/workload2", &err);
    _svid1.certs = (X509 **) 1;
    _svid2.certs = (X509 **) 2;
    _svid1.id = id1;
    _svid2.id = id2;
    _svid1.private_key = NULL;
    _svid2.private_key = NULL;

    tested->svids = NULL;

    arrpush(tested->svids, svid1);
    arrpush(tested->svids, svid2);
    tested->closed = false;
    x509svid_SVID *svid3 = workloadapi_X509Source_GetX509SVID(tested, &err);

    ck_assert_ptr_eq(svid3, svid1);
    arrpop(tested->svids);
    arrpop(tested->svids);
    workloadapi_X509Source_Free(tested);
}
END_TEST

START_TEST(test_workloadapi_X509Source_GetX509SVID_custom_picker);
{
    err_t err;
    workloadapi_X509SourceConfig config;
    config.picker = custom_picker;
    config.watcher_config.client_options = NULL;
    config.watcher_config.client = NULL;

    workloadapi_X509Source *tested = workloadapi_NewX509Source(&config, &err);

    x509svid_SVID _svid1;
    x509svid_SVID _svid2;
    x509svid_SVID *svid1 = &_svid1;
    x509svid_SVID *svid2 = &_svid2;
    spiffeid_ID id1
        = spiffeid_FromString("spiffe://example.org/workload1", &err);
    spiffeid_ID id2
        = spiffeid_FromString("spiffe://example.org/workload2", &err);
    _svid1.certs = (X509 **) 1;
    _svid2.certs = (X509 **) 2;
    _svid1.id = id1;
    _svid2.id = id2;
    _svid1.private_key = NULL;
    _svid2.private_key = NULL;

    tested->svids = NULL;

    arrpush(tested->svids, svid1);
    arrpush(tested->svids, svid2);
    tested->closed = false;

    x509svid_SVID *svid3 = workloadapi_X509Source_GetX509SVID(tested, &err);

    ck_assert_ptr_eq(svid3, svid2);
    arrpop(tested->svids);
    arrpop(tested->svids);
    workloadapi_X509Source_Free(tested);
}
END_TEST

START_TEST(test_workloadapi_X509Source_applyX509Context);
{
    err_t err;
    workloadapi_X509Source *tested = workloadapi_NewX509Source(NULL, &err);

    workloadapi_X509Context ctx;
    ctx.bundles = (x509bundle_Set *) 1;
    ctx.svids = (x509svid_SVID **) 2;

    workloadapi_X509Source_applyX509Context(tested, &ctx);

    ck_assert_ptr_eq(tested->bundles, (x509bundle_Set *) 1);

    ck_assert_ptr_eq(tested->svids, (x509svid_SVID **) 2);

    tested->bundles = NULL;
    tested->svids = NULL;
    workloadapi_X509Source_Free(tested);
}
END_TEST

int waitAndUpdate(void *args)
{
    struct timespec now = { 3, 0 };
    thrd_sleep(&now, NULL);
    ck_assert(!((workloadapi_X509Source *) args)->closed);
    workloadapi_Watcher_TriggerUpdated(
        ((workloadapi_X509Source *) args)->watcher);
    return 0;
}

START_TEST(test_workloadapi_X509Source_Start_waits_and_sets_closed_false);
{
    err_t err;
    workloadapi_X509Source *tested = workloadapi_NewX509Source(NULL, &err);
    struct timespec then;
    timespec_get(&then, TIME_UTC);
    thrd_t thread;
    thrd_create(&thread, waitAndUpdate, tested);

    workloadapi_X509Source_Start(tested);

    struct timespec now;
    timespec_get(&now, TIME_UTC);

    ck_assert_int_ge(now.tv_sec, then.tv_sec + 2);
    ck_assert_int_lt(now.tv_sec, then.tv_sec + 5);

    ck_assert_int_eq(workloadapi_X509Source_checkClosed(tested), NO_ERROR);

    workloadapi_X509Source_Close(tested);

    tested->bundles = NULL;
    tested->svids = NULL;
    workloadapi_X509Source_Free(tested);
}
END_TEST

START_TEST(test_workloadapi_X509Source_Closes_watcher);
{
    err_t err;
    workloadapi_X509Source *tested = workloadapi_NewX509Source(NULL, &err);
    struct timespec then;
    timespec_get(&then, TIME_UTC);
    thrd_t thread;
    thrd_create(&thread, waitAndUpdate, tested);

    workloadapi_X509Source_Start(tested);

    struct timespec now;
    timespec_get(&now, TIME_UTC);

    ck_assert_int_ge(now.tv_sec, then.tv_sec + 2);
    ck_assert_int_lt(now.tv_sec, then.tv_sec + 5);

    ck_assert_int_eq(workloadapi_X509Source_checkClosed(tested), NO_ERROR);
    ck_assert(!tested->watcher->closed);

    workloadapi_X509Source_Close(tested);

    ck_assert_int_eq(workloadapi_X509Source_checkClosed(tested), ERR_CLOSED);
    ck_assert(tested->watcher->closed);

    tested->bundles = NULL;
    tested->svids = NULL;
    workloadapi_X509Source_Free(tested);
}
END_TEST

START_TEST(test_workloadapi_X509Source_GetX509BundleForTrustDomain);
{
    err_t err;
    workloadapi_X509Source *tested = workloadapi_NewX509Source(NULL, &err);
    const char td_url[] = "example.org";
    spiffeid_TrustDomain td = spiffeid_TrustDomainFromString(td_url, &err);

    x509bundle_Bundle *bundle
        = workloadapi_X509Source_GetX509BundleForTrustDomain(tested, td, &err);

    ck_assert_ptr_eq(bundle, NULL);
    ck_assert_int_eq(err, ERR_CLOSED); // source closed

    tested->closed = false;
    tested->bundles = x509bundle_NewSet(0);
    bundle
        = workloadapi_X509Source_GetX509BundleForTrustDomain(tested, td, &err);

    ck_assert_ptr_eq(bundle, NULL);
    ck_assert_int_eq(err, ERR_CLOSED); // trust domain not available

    x509bundle_Set_Free(tested->bundles);
    tested->bundles = NULL;
    tested->closed = true;
    workloadapi_X509Source_Free(tested);
}
END_TEST

Suite *watcher_suite(void)
{
    Suite *s = suite_create("x509source");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core,
                   test_workloadapi_NewX509Source_creates_default_config);
    tcase_add_test(tc_core, test_workloadapi_NewX509Source_uses_config);
    tcase_add_test(tc_core,
                   test_workloadapi_X509Source_GetX509SVID_default_picker);
    tcase_add_test(tc_core,
                   test_workloadapi_X509Source_GetX509SVID_custom_picker);
    tcase_add_test(tc_core, test_workloadapi_X509Source_applyX509Context);
    tcase_add_test(
        tc_core,
        test_workloadapi_X509Source_Start_waits_and_sets_closed_false);
    tcase_add_test(tc_core, test_workloadapi_X509Source_Closes_watcher);
    tcase_add_test(tc_core,
                   test_workloadapi_X509Source_GetX509BundleForTrustDomain);

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
