#include "c-spiffe/federation/watcher.h"
#include "c-spiffe/spiffeid/trustdomain.h"
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
    spiffeid_TrustDomain null_td = { NULL };
    const char url[]
        = "https://raw.githubusercontent.com/HewlettPackard/c-spiffe/master/"
          "bundle/jwtbundle/tests/resources/jwk_keys.json";
    err_t err = spiffebundle_Watcher_AddHttpsWebEndpoint(watcher, url, td);

    ck_assert_uint_eq(err, NO_ERROR);
    err = spiffebundle_Watcher_AddHttpsWebEndpoint(NULL, NULL, td);
    ck_assert_uint_ne(err, NO_ERROR);

    err = spiffebundle_Watcher_AddHttpsWebEndpoint(watcher, NULL, td);
    ck_assert_uint_ne(err, NO_ERROR);

    err = spiffebundle_Watcher_AddHttpsWebEndpoint(watcher, url, null_td);
    ck_assert_uint_ne(err, NO_ERROR);
    const int idx = shgeti(watcher->endpoints, td.name);

    ck_assert_int_ge(idx, 0);
    ck_assert_ptr_ne(watcher->endpoints[idx].value->endpoint, NULL);

    spiffebundle_Watcher_Free(watcher);
}
END_TEST

START_TEST(test_spiffebundle_Watcher_StartHttpsWebEndpoint)
{
    system("go run ./resources/https_web_server.go 127.0.0.1:8443 &");

    struct timespec sleep_time = { .tv_sec = 1, .tv_nsec = 0 };
    nanosleep(&sleep_time,
              NULL); // sleep for a second to let the server set itself up

    spiffebundle_Watcher *watcher = spiffebundle_Watcher_New();
    spiffeid_TrustDomain td = { "example.org" };
    const char url[] = "https://example.org:8443";
    err_t err = spiffebundle_Watcher_AddHttpsWebEndpoint(watcher, url, td);
    ck_assert_uint_eq(err, NO_ERROR);

    const int idx = shgeti(watcher->endpoints, td.name);

    ck_assert_int_ge(idx, 0);
    ck_assert_ptr_ne(watcher->endpoints[idx].value->endpoint, NULL);

    // set certs for localhost
    watcher->endpoints[idx].value->endpoint->curl_handle = curl_easy_init();
    curl_easy_setopt(watcher->endpoints[idx].value->endpoint->curl_handle,
                     CURLOPT_CAINFO, "./resources/example.org.crt");
    struct curl_slist *resolve_list = NULL;
    resolve_list
        = curl_slist_append(resolve_list, "example.org:8443:127.0.0.1");
    curl_easy_setopt(watcher->endpoints[idx].value->endpoint->curl_handle,
                     CURLOPT_RESOLVE, resolve_list);
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
    curl_slist_free_all(resolve_list);
}
END_TEST

START_TEST(test_spiffebundle_Watcher_AddHttpsSpiffeEndpoint)
{
    spiffebundle_Watcher *watcher = spiffebundle_Watcher_New();
    spiffeid_TrustDomain td = { "example.org" };
    spiffeid_TrustDomain null_td = { NULL };
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

    err = spiffebundle_Watcher_AddHttpsSpiffeEndpoint(watcher, NULL, td, NULL,
                                                      source);
    ck_assert_uint_ne(err, NO_ERROR);

    err = spiffebundle_Watcher_AddHttpsSpiffeEndpoint(watcher, url, null_td,
                                                      str_id, source);
    ck_assert_uint_ne(err, NO_ERROR);

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
    system("go run ./resources/https_spiffe_server.go 127.0.0.1:8443 &");
    struct timespec sleep_time = { .tv_sec = 1, .tv_nsec = 0 };
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
    const char url[] = "https://example.org:8443";
    const char str_id[] = "spiffe://example.org/workload";
    err = spiffebundle_Watcher_AddHttpsSpiffeEndpoint(watcher, url, td, str_id,
                                                      source);

    ck_assert_uint_eq(err, NO_ERROR);

    const int idx = shgeti(watcher->endpoints, td.name);

    ck_assert_int_ge(idx, 0);
    ck_assert_ptr_ne(watcher->endpoints[idx].value->endpoint, NULL);
    watcher->endpoints[idx].value->endpoint->curl_handle = curl_easy_init();
    struct curl_slist *resolve_list = NULL;
    resolve_list
        = curl_slist_append(resolve_list, "example.org:8443:127.0.0.1");
    curl_easy_setopt(watcher->endpoints[idx].value->endpoint->curl_handle,
                     CURLOPT_RESOLVE, resolve_list);
    spiffebundle_Watcher_Start(watcher);
    nanosleep(&sleep_time, NULL);
    ck_assert_int_eq(watcher->endpoints[idx].value->running, 1);
    spiffebundle_Bundle *retbundle
        = spiffebundle_Watcher_GetBundleForTrustDomain(watcher, td, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(retbundle, NULL);
    spiffebundle_Watcher_Stop(watcher);
    ck_assert_int_eq(watcher->endpoints[idx].value->running, 0);

    spiffebundle_Watcher_Free(watcher);
    spiffebundle_Source_Free(source);

    curl_slist_free_all(resolve_list);
}
END_TEST

START_TEST(test_spiffebundle_Watcher_Start)
{
    spiffebundle_Watcher *watcher = spiffebundle_Watcher_New();
    err_t err = spiffebundle_Watcher_Start(NULL);
    ck_assert_uint_eq(err, ERR_STARTING);

    err = spiffebundle_Watcher_Start(watcher);
    ck_assert_uint_eq(err, NO_ERROR);
    
    struct timespec sleep_time = { 0, 200000000 };
    nanosleep(&sleep_time, NULL);
    
    err = spiffebundle_Watcher_Stop(NULL);
    ck_assert_uint_eq(err, ERR_STOPPING);

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
    //not found
    spiffebundle_Bundle *bundle
        = spiffebundle_Watcher_GetBundleForTrustDomain(watcher, td, &err);
    ck_assert_ptr_eq(bundle, NULL);
    ck_assert_uint_ne(err, NO_ERROR);
    
    //null tests
    spiffeid_TrustDomain null_td = { NULL };
    bundle = spiffebundle_Watcher_GetBundleForTrustDomain(NULL, td, &err);
    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert_ptr_eq(bundle, NULL);
    bundle = spiffebundle_Watcher_GetBundleForTrustDomain(watcher, null_td, &err);
    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert_ptr_eq(bundle, NULL);

    spiffebundle_Watcher_Free(watcher);
}
END_TEST

START_TEST(test_spiffebundle_Watcher_GetStatus)
{
    spiffebundle_Watcher *watcher = spiffebundle_Watcher_New();

    spiffeid_TrustDomain td = { "example.org" };
    err_t err;
    int running_status = spiffebundle_Watcher_GetStatus(NULL, td, &err);
    ck_assert_uint_eq(err, ERR_NULL);
    ck_assert_int_eq(running_status, ENDPOINT_ERROR);

    spiffeid_TrustDomain null_td = { NULL };
    running_status = spiffebundle_Watcher_GetStatus(watcher, null_td, &err);
    ck_assert_uint_eq(err, ERR_INVALID_DATA);
    ck_assert_int_eq(running_status, ENDPOINT_ERROR);

    running_status = spiffebundle_Watcher_GetStatus(watcher, td, &err);
    ck_assert_uint_eq(err, ERR_NULL);
    ck_assert_int_eq(running_status, ENDPOINT_ERROR);

    const char url[] = "https://example.org";
    err = spiffebundle_Watcher_AddHttpsWebEndpoint(watcher, url, td);
    ck_assert_uint_eq(err, NO_ERROR);

    const int idx = shgeti(watcher->endpoints, td.name);
    running_status = spiffebundle_Watcher_GetStatus(watcher, td, &err);
    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_int_eq(running_status, 0);

    watcher->endpoints[idx].value->running = 99;
    running_status = spiffebundle_Watcher_GetStatus(watcher, td, &err);
    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_int_eq(running_status, 99);

    spiffebundle_Watcher_Free(watcher);
}
END_TEST

Suite *watcher_suite(void)
{
    Suite *s = suite_create("spiffebundle_watcher");
    TCase *tc_core = tcase_create("core");
    tcase_add_test(tc_core, test_spiffebundle_Watcher_StartHttpsWebEndpoint);
    tcase_add_test(tc_core,
                   test_spiffebundle_Watcher_StartHttpsSpiffeEndpoint);
    tcase_add_test(tc_core, test_spiffebundle_Watcher_New);
    tcase_add_test(tc_core, test_spiffebundle_Watcher_AddHttpsWebEndpoint);
    tcase_add_test(tc_core, test_spiffebundle_Watcher_AddHttpsSpiffeEndpoint);
    tcase_add_test(tc_core, test_spiffebundle_Watcher_Start);
    tcase_add_test(tc_core, test_spiffebundle_Watcher_Stop);
    tcase_add_test(tc_core, test_spiffebundle_Watcher_GetBundleForTrustDomain);
    tcase_add_test(tc_core, test_spiffebundle_Watcher_GetStatus);

    tcase_set_timeout(tc_core, 20);
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
