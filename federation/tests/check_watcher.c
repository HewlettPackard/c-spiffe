#include "federation/src/watcher.h"
#include "spiffeid/src/trustdomain.h"
#include <check.h>
#include <unistd.h>

START_TEST(test_spiffebundle_Watcher_New)
{
    spiffebundle_Watcher *watcher = spiffebundle_Watcher_New();

    ck_assert_ptr_ne(watcher, NULL);
    ck_assert_ptr_ne(watcher->endpoints, NULL);

    spiffebundle_Watcher_Free(watcher);
}
END_TEST

START_TEST(test_spiffebundle_Watcher_AddHttpsWebEndpoint)
{
    spiffebundle_Watcher *watcher = spiffebundle_Watcher_New();
    spiffeid_TrustDomain td = { "example.org" };
    const char url[]
        = "https://raw.githubusercontent.com/HewlettPackard/c-spiffe/master/"
          "bundle/jwtbundle/tests/resources/jwk_keys.json";
    err_t err = spiffebundle_Watcher_AddHttpsWebEndpoint(watcher, url, td);

    ck_assert_uint_eq(err, NO_ERROR);

    const int idx = shgeti(watcher->endpoints, td.name);

    ck_assert_int_ge(idx, 0);
    ck_assert_ptr_ne(watcher->endpoints[idx].value->endpoint, NULL);

    spiffebundle_Watcher_Free(watcher);
}
END_TEST

START_TEST(test_spiffebundle_Watcher_StartHttpsWebEndpoint)
{
    system("go run ./resources/https_web_server.go &");

    struct timespec sleep_time = { 1, 000000000 };
    nanosleep(&sleep_time,
              NULL); // sleep for a second to let the server set itself up

    spiffebundle_Watcher *watcher = spiffebundle_Watcher_New();
    spiffeid_TrustDomain td = { "example.org" };
    const char url[] = "https://example.org";
    err_t err = spiffebundle_Watcher_AddHttpsWebEndpoint(watcher, url, td);
    ck_assert_uint_eq(err, NO_ERROR);

    const int idx = shgeti(watcher->endpoints, td.name);

    ck_assert_int_ge(idx, 0);
    ck_assert_ptr_ne(watcher->endpoints[idx].value->endpoint, NULL);

    // set certs for localhost
    watcher->endpoints[idx].value->endpoint->curl_handle = curl_easy_init();
    curl_easy_setopt(watcher->endpoints[idx].value->endpoint->curl_handle,
                     CURLOPT_CAINFO, "./resources/example.org.crt");

    spiffebundle_Watcher_Start(watcher);

    nanosleep(&sleep_time, NULL);

    ck_assert_int_eq(watcher->endpoints[idx].value->running, 1);
    spiffebundle_Bundle *bundle
        = spiffebundle_Watcher_GetBundleForTrustDomain(watcher, td, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(bundle, NULL);

    spiffebundle_Watcher_Stop(watcher);

    nanosleep(&sleep_time, NULL);
    ck_assert_int_eq(watcher->endpoints[idx].value->running, 0);
    spiffebundle_Watcher_Free(watcher);
}
END_TEST

START_TEST(test_spiffebundle_Watcher_AddHttpsSpiffeEndpoint)
{
    spiffebundle_Watcher *watcher = spiffebundle_Watcher_New();
    spiffeid_TrustDomain td = { "example.org" };
    err_t err;
    spiffebundle_Bundle *bundle
        = spiffebundle_Load(td, "./resources/jwks_valid_2.json", &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(bundle, NULL);

    spiffebundle_Source *source = spiffebundle_SourceFromBundle(bundle);
    const char url[]
        = "https://raw.githubusercontent.com/HewlettPackard/c-spiffe/master/"
          "bundle/jwtbundle/tests/resources/jwk_keys.json";
    const char str_id[] = "spiffe://example.org/workload";
    err = spiffebundle_Watcher_AddHttpsSpiffeEndpoint(watcher, url, td, str_id,
                                                      source);

    ck_assert_uint_eq(err, NO_ERROR);

    const int idx = shgeti(watcher->endpoints, td.name);

    ck_assert_int_ge(idx, 0);
    ck_assert_ptr_ne(watcher->endpoints[idx].value->endpoint, NULL);

    spiffebundle_Watcher_Free(watcher);
    spiffebundle_Source_Free(source);
}
END_TEST

START_TEST(test_spiffebundle_Watcher_StartHttpsSpiffeEndpoint)
{
    system("go run ./resources/https_spiffe_server.go &");
    struct timespec sleep_time = { 2, 000000000 };
    nanosleep(&sleep_time,
              NULL); // sleep for a second to let the server set itself up
    spiffebundle_Watcher *watcher = spiffebundle_Watcher_New();
    spiffeid_TrustDomain td = { "example.org" };
    err_t err;

    x509bundle_Bundle *x509_bundle
        = x509bundle_Load(td, "./resources/example.org.crt", &err);

    ck_assert_uint_eq(err, NO_ERROR);
    spiffebundle_Bundle *bundle = spiffebundle_FromX509Bundle(x509_bundle);

    ck_assert_ptr_ne(bundle, NULL);

    spiffebundle_Source *source = spiffebundle_SourceFromBundle(bundle);
    const char url[] = "https://example.org:443";
    const char str_id[] = "spiffe://example.org/workload";
    err = spiffebundle_Watcher_AddHttpsSpiffeEndpoint(watcher, url, td, str_id,
                                                      source);

    ck_assert_uint_eq(err, NO_ERROR);

    const int idx = shgeti(watcher->endpoints, td.name);

    ck_assert_int_ge(idx, 0);
    ck_assert_ptr_ne(watcher->endpoints[idx].value->endpoint, NULL);

    spiffebundle_Watcher_Start(watcher);
    nanosleep(&sleep_time, NULL);
    ck_assert_int_eq(watcher->endpoints[idx].value->running, 1);

    spiffebundle_Watcher_Stop(watcher);
    ck_assert_int_eq(watcher->endpoints[idx].value->running, 0);

    spiffebundle_Watcher_Free(watcher);
    spiffebundle_Source_Free(source);
}
END_TEST

START_TEST(test_spiffebundle_Watcher_Start)
{
    spiffebundle_Watcher *watcher = spiffebundle_Watcher_New();
    err_t err = spiffebundle_Watcher_Start(watcher);
    ck_assert_uint_eq(err, NO_ERROR);

    struct timespec sleep_time = { 0, 200000000 };
    nanosleep(&sleep_time, NULL);

    err = spiffebundle_Watcher_Stop(watcher);

    ck_assert_uint_eq(err, NO_ERROR);
    spiffebundle_Watcher_Free(watcher);
}
END_TEST

START_TEST(test_spiffebundle_Watcher_Stop)
{
    spiffebundle_Watcher *watcher = spiffebundle_Watcher_New();
    err_t err = spiffebundle_Watcher_Start(watcher);
    err = spiffebundle_Watcher_Stop(watcher);

    ck_assert_uint_eq(err, NO_ERROR);

    spiffebundle_Watcher_Free(watcher);
}
END_TEST

START_TEST(test_spiffebundle_Watcher_GetBundleForTrustDomain)
{
    spiffebundle_Watcher *watcher = spiffebundle_Watcher_New();

    spiffeid_TrustDomain td = { "example.org" };
    err_t err;
    spiffebundle_Bundle *bundle
        = spiffebundle_Watcher_GetBundleForTrustDomain(watcher, td, &err);

    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert_ptr_eq(bundle, NULL);

    /// TODO: add bundle to watcher

    spiffebundle_Watcher_Free(watcher);
}
END_TEST

Suite *watcher_suite(void)
{
    Suite *s = suite_create("spiffebundle_watcher");
    TCase *tc_core = tcase_create("core");
    // tcase_add_test(tc_core, test_spiffebundle_Watcher_StartHttpsWebEndpoint);
    tcase_add_test(tc_core,
                   test_spiffebundle_Watcher_StartHttpsSpiffeEndpoint);
    // tcase_add_test(tc_core, test_spiffebundle_Watcher_New);
    // tcase_add_test(tc_core, test_spiffebundle_Watcher_AddHttpsWebEndpoint);
    // tcase_add_test(tc_core, test_spiffebundle_Watcher_AddHttpsSpiffeEndpoint);
    // tcase_add_test(tc_core, test_spiffebundle_Watcher_Start);
    // tcase_add_test(tc_core, test_spiffebundle_Watcher_Stop);
    // tcase_add_test(tc_core, test_spiffebundle_Watcher_GetBundleForTrustDomain);

    tcase_set_timeout(tc_core,20);
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
