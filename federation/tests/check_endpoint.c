#include "c-spiffe/bundle/spiffebundle/source.h"
#include "c-spiffe/federation/endpoint.h"
#include <check.h>
#include <unistd.h>

START_TEST(test_federation_Endpoint_New_and_free);
{
    err_t err = NO_ERROR;
    spiffebundle_Endpoint *tested = spiffebundle_Endpoint_New();
    ck_assert_ptr_ne(tested, NULL);
    spiffeid_TrustDomain td
        = spiffeid_TrustDomainFromString("example.com", &err);
    ck_assert_int_eq(err, NO_ERROR);
    const char *sid = "spiffe://example.com/workload1";

    spiffebundle_Bundle *bundle
        = spiffebundle_Load(td, "./resources/jwks_valid_2.json", &err);
    ck_assert_int_eq(err, NO_ERROR);
    spiffebundle_Source *bundle_source = spiffebundle_SourceFromBundle(bundle);
    spiffebundle_Endpoint_ConfigHTTPSSPIFFE(tested, "example.com/bundle.json",
                                            td, sid, bundle_source);
    tested->owns_bundle = true;

    spiffebundle_Endpoint_Free(tested);
}
END_TEST

START_TEST(test_federation_Endpoint_Config_SPIFFE);
{
    err_t err = NO_ERROR;
    spiffebundle_Endpoint *tested = spiffebundle_Endpoint_New();
    spiffeid_TrustDomain td
        = spiffeid_TrustDomainFromString("example.com", &err);
    ck_assert_int_eq(err, NO_ERROR);
    const char *sid = "spiffe://example.com/workload1";
    ck_assert_int_eq(err, NO_ERROR);

    spiffebundle_Bundle *bundle
        = spiffebundle_Load(td, "./resources/jwks_valid_2.json", &err);
    ck_assert_int_eq(err, NO_ERROR);
    spiffebundle_Source *bundle_source = spiffebundle_SourceFromBundle(bundle);

    err = spiffebundle_Endpoint_ConfigHTTPSSPIFFE(
        NULL, "example.com/bundle.json", td, sid, bundle_source);
    ck_assert_int_eq(err, ERR_NULL);

    err = spiffebundle_Endpoint_ConfigHTTPSSPIFFE(tested, NULL, td, sid,
                                                  bundle_source);
    ck_assert_int_eq(err, ERR_EMPTY_DATA);

    err = spiffebundle_Endpoint_ConfigHTTPSSPIFFE(tested, "not an URL", td,
                                                  sid, bundle_source);
    ck_assert_int_eq(err, ERR_INVALID_DATA);

    spiffeid_TrustDomain err_td = { NULL };
    err = spiffebundle_Endpoint_ConfigHTTPSSPIFFE(
        tested, "example.com/bundle.json", err_td, sid, bundle_source);
    ck_assert_int_eq(err, ERR_INVALID_TRUSTDOMAIN);
    spiffeid_TrustDomain err_td2 = { "not_a_td://NU,,LL" };
    err = spiffebundle_Endpoint_ConfigHTTPSSPIFFE(
        tested, "example.com/bundle.json", err_td2, sid, bundle_source);
    ck_assert_int_eq(err, ERR_INVALID_TRUSTDOMAIN);

    string_t err_id = "https://not.a.spiffe.id/wrong";
    err = spiffebundle_Endpoint_ConfigHTTPSSPIFFE(
        tested, "example.com/bundle.json", td, err_id, bundle_source);
    ck_assert_int_eq(err, ERR_PARSING);

    err = spiffebundle_Endpoint_ConfigHTTPSSPIFFE(
        tested, "example.com/bundle.json", td, sid, NULL);
    ck_assert_int_eq(err, ERR_INVALID_DATA);

    err = spiffebundle_Endpoint_ConfigHTTPSSPIFFE(
        tested, "example.com/bundle.json", td, sid, bundle_source);
    ck_assert_int_eq(err, NO_ERROR);

    tested->owns_bundle = true;
    spiffebundle_Endpoint_Free(tested);
}
END_TEST

START_TEST(test_federation_Endpoint_Config_WEB);
{
    err_t err = NO_ERROR;
    spiffebundle_Endpoint *tested = spiffebundle_Endpoint_New();
    spiffeid_TrustDomain td
        = spiffeid_TrustDomainFromString("example.com", &err);
    ck_assert_int_eq(err, NO_ERROR);

    err = spiffebundle_Endpoint_ConfigHTTPSWEB(NULL, "example.com/bundle.json",
                                               td);
    ck_assert_int_eq(err, ERR_NULL);

    err = spiffebundle_Endpoint_ConfigHTTPSWEB(tested, NULL, td);
    ck_assert_int_eq(err, ERR_EMPTY_DATA);

    err = spiffebundle_Endpoint_ConfigHTTPSWEB(tested, "not a URL", td);
    ck_assert_int_eq(err, ERR_PARSING);

    spiffeid_TrustDomain err_td = { NULL };
    err = spiffebundle_Endpoint_ConfigHTTPSWEB(
        tested, "example.com/bundle.json", err_td);
    ck_assert_int_eq(err, ERR_INVALID_TRUSTDOMAIN);
    spiffeid_TrustDomain err_td2 = { "not_a_td://NU,,LL" };
    err = spiffebundle_Endpoint_ConfigHTTPSWEB(
        tested, "example.com/bundle.json", err_td2);
    ck_assert_int_eq(err, ERR_INVALID_TRUSTDOMAIN);

    err = spiffebundle_Endpoint_ConfigHTTPSWEB(tested,
                                               "example.com/bundle.json", td);
    ck_assert_int_eq(err, NO_ERROR);

    tested->owns_bundle = true;
    spiffebundle_Endpoint_Free(tested);
}
END_TEST

START_TEST(test_federation_Endpoint_get_bundle);
{
    spiffebundle_Endpoint *tested = spiffebundle_Endpoint_New();
    err_t err;
    spiffeid_TrustDomain td = { string_new("example1.com") };
    spiffebundle_Bundle *bundle
        = spiffebundle_Load(td, "./resources/jwks_valid_2.json", &err);

    ck_assert_uint_eq(err, NO_ERROR);

    spiffebundle_Set *set = spiffebundle_NewSet(1, bundle);
    spiffebundle_Source *source = spiffebundle_SourceFromSet(set);
    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(source, NULL);

    spiffebundle_Bundle *end_bundle
        = spiffebundle_Endpoint_GetBundleForTrustDomain(NULL, td, &err);
    ck_assert_uint_eq(err, ERR_NULL);

    spiffeid_TrustDomain err_td = { NULL };
    end_bundle
        = spiffebundle_Endpoint_GetBundleForTrustDomain(tested, err_td, &err);
    ck_assert_uint_eq(err, ERR_TRUSTDOMAIN_NOTAVAILABLE);

    tested->source = NULL;
    end_bundle
        = spiffebundle_Endpoint_GetBundleForTrustDomain(tested, td, &err);
    ck_assert_uint_eq(err, ERR_NULL);

    tested->source = source;
    end_bundle
        = spiffebundle_Endpoint_GetBundleForTrustDomain(tested, td, &err);
    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_eq(bundle, end_bundle);

    tested->owns_bundle = true;
    spiffeid_TrustDomain_Free(&td);
    spiffebundle_Source_Free(source);
}
END_TEST

START_TEST(test_federation_Endpoint_fetch_WEB);
{
    system("go run ./resources/https_web_server.go 127.0.0.1:443 &");

    struct timespec sleep_time = { .tv_sec = 1, .tv_nsec = 0 };
    nanosleep(&sleep_time,
              NULL); // sleep for a second to let the server set itself up
    spiffebundle_Endpoint *tested = spiffebundle_Endpoint_New();
    err_t err;
    spiffeid_TrustDomain td = { string_new("example.org") };
    spiffebundle_Bundle *bundle
        = spiffebundle_Load(td, "./resources/example.org.bundle.jwks", &err);

    ck_assert_uint_eq(err, NO_ERROR);
    err = spiffebundle_Endpoint_ConfigHTTPSWEB(tested,
                                               "https://example.org:443", td);

    ck_assert_int_eq(err, NO_ERROR);
    tested->curl_handle = curl_easy_init();

    // set certs for localhost
    curl_easy_setopt(tested->curl_handle, CURLOPT_CAINFO,
                     "./resources/example.org.crt");
    // set hostname resolution
    struct curl_slist *resolve_list = NULL;
    resolve_list
        = curl_slist_append(resolve_list, "example.org:443:127.0.0.1");
    curl_easy_setopt(tested->curl_handle, CURLOPT_RESOLVE, resolve_list);

    err = spiffebundle_Endpoint_Fetch(tested);
    nanosleep(&sleep_time, NULL);
    ck_assert_ptr_ne(tested->source, NULL);

    ck_assert(spiffebundle_Bundle_Equal(
        bundle,
        spiffebundle_Endpoint_GetBundleForTrustDomain(tested, td, &err)));
    ck_assert_int_eq(err, NO_ERROR);

    bundle = spiffebundle_Load(td, "./resources/jwks_valid_1.json", &err);

    ck_assert(!spiffebundle_Bundle_Equal(
        bundle,
        spiffebundle_Endpoint_GetBundleForTrustDomain(tested, td, &err)));
    ck_assert_uint_eq(err, NO_ERROR);
    spiffeid_TrustDomain_Free(&td);
    curl_slist_free_all(resolve_list);
}
END_TEST

START_TEST(test_federation_Endpoint_fetch_SPIFFE);
{
    system("go run ./resources/https_spiffe_server.go 127.0.0.1:443 &");

    struct timespec sleep_time = { .tv_sec = 1, .tv_nsec = 0 };
    nanosleep(&sleep_time,
              NULL); // sleep for half a second to let the server set itself up
    err_t err;
    spiffeid_TrustDomain td = { "example.org" };
    spiffeid_TrustDomain null_td = { NULL };
    x509bundle_Bundle *x509bundle
        = x509bundle_Load(td, "./resources/example.org.crt", &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(x509bundle, NULL);

    spiffebundle_Bundle *bundle = spiffebundle_FromX509Bundle(x509bundle);
    ck_assert_uint_eq(err, NO_ERROR);

    spiffebundle_Source *source = spiffebundle_SourceFromBundle(bundle);
    spiffebundle_Endpoint *tested = spiffebundle_Endpoint_New();

    err = spiffebundle_Endpoint_ConfigHTTPSSPIFFE(
        tested, "https://example.org:443", td, "spiffe://example.org/workload",
        source);

    ck_assert_ptr_ne(tested->source, NULL);
    ck_assert_ptr_eq(tested->source, source);
    ck_assert_int_eq(err, NO_ERROR);
    tested->curl_handle = curl_easy_init();

    // set example.org -> 127.0.0.1
    struct curl_slist *resolve_list = NULL;
    resolve_list
        = curl_slist_append(resolve_list, "example.org:443:127.0.0.1");
    curl_easy_setopt(tested->curl_handle, CURLOPT_RESOLVE, resolve_list);
    
    err = spiffebundle_Endpoint_Fetch(NULL);
    ck_assert_int_eq(err, ERR_NULL);
    tested->td = null_td;
    err = spiffebundle_Endpoint_Fetch(tested);
    ck_assert_int_eq(err, ERR_INVALID_DATA);
    tested->td = td;

    err = spiffebundle_Endpoint_Fetch(tested);
    nanosleep(&sleep_time, NULL);
    ck_assert_int_eq(err, NO_ERROR);
    ck_assert_ptr_ne(tested->source, NULL);
    ck_assert(tested->owns_bundle);

    for(size_t i = 0,
               size = arrlenu(spiffebundle_Bundle_X509Authorities(bundle));
        i < size; ++i) {
        ck_assert(spiffebundle_Bundle_HasX509Authority(
            spiffebundle_Endpoint_GetBundleForTrustDomain(tested, td, &err),
            spiffebundle_Bundle_X509Authorities(bundle)[i]));
    }

    ck_assert_int_eq(err, NO_ERROR);

    bundle = spiffebundle_Load(td, "./resources/jwks_valid_1.json", &err);

    ck_assert(!spiffebundle_Bundle_Equal(
        bundle,
        spiffebundle_Endpoint_GetBundleForTrustDomain(tested, td, &err)));

    ck_assert_uint_eq(err, NO_ERROR);

    bundle
        = spiffebundle_Load(td, "./resources/example.org.bundle.jwks", &err);

    ck_assert(spiffebundle_Bundle_Equal(
        bundle,
        spiffebundle_Endpoint_GetBundleForTrustDomain(tested, td, &err)));

    ck_assert_uint_eq(err, NO_ERROR);
    spiffebundle_Endpoint_Free(tested);
    curl_slist_free_all(resolve_list);
}
END_TEST

Suite *watcher_suite(void)
{
    Suite *s = suite_create("spiffebundle_endpoint");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_federation_Endpoint_New_and_free);
    tcase_add_test(tc_core, test_federation_Endpoint_Config_SPIFFE);
    tcase_add_test(tc_core, test_federation_Endpoint_Config_WEB);
    tcase_add_test(tc_core, test_federation_Endpoint_get_bundle);
    tcase_add_test(tc_core, test_federation_Endpoint_fetch_WEB);
    tcase_add_test(tc_core, test_federation_Endpoint_fetch_SPIFFE);

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
