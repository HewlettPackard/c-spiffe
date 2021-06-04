#include "bundle/spiffebundle/src/source.h"
#include "federation/src/endpoint.h"
#include <check.h>

START_TEST(test_federation_Endpoint_New_and_free);
{
    err_t err = NO_ERROR;
    spiffebundle_Endpoint *tested = spiffebundle_Endpoint_New();
    ck_assert_ptr_ne(tested, NULL);
    spiffeid_TrustDomain td
        = spiffeid_TrustDomainFromString("example.com", &err);
    ck_assert_int_eq(err, NO_ERROR);
    string_t sid = "spiffe://example.com/workload1";

    spiffebundle_Bundle *bundle
        = spiffebundle_Load(td, "./resources/jwks_valid_2.json", &err);
    ck_assert_int_eq(err, NO_ERROR);
    spiffebundle_Source *bundle_source = spiffebundle_SourceFromBundle(bundle);
    spiffebundle_Endpoint_Config_HTTPS_SPIFFE(
        tested, "example.com/bundle.json", td, sid, bundle_source);
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
    string_t sid = "spiffe://example.com/workload1";
    ck_assert_int_eq(err, NO_ERROR);

    spiffebundle_Bundle *bundle
        = spiffebundle_Load(td, "./resources/jwks_valid_2.json", &err);
    ck_assert_int_eq(err, NO_ERROR);
    spiffebundle_Source *bundle_source = spiffebundle_SourceFromBundle(bundle);

    err = spiffebundle_Endpoint_Config_HTTPS_SPIFFE(
        NULL, "example.com/bundle.json", td, sid, bundle_source);
    ck_assert_int_eq(err, ERROR1);

    err = spiffebundle_Endpoint_Config_HTTPS_SPIFFE(tested, NULL, td, sid,
                                                    bundle_source);
    ck_assert_int_eq(err, ERROR2);

    err = spiffebundle_Endpoint_Config_HTTPS_SPIFFE(tested, "not a URL", td,
                                                    sid, bundle_source);
    ck_assert_int_eq(err, ERROR2);

    spiffeid_TrustDomain err_td = { NULL };
    err = spiffebundle_Endpoint_Config_HTTPS_SPIFFE(
        tested, "example.com/bundle.json", err_td, sid, bundle_source);
    ck_assert_int_eq(err, ERROR3);
    spiffeid_TrustDomain err_td2 = { "not_a_td://NU,,LL" };
    err = spiffebundle_Endpoint_Config_HTTPS_SPIFFE(
        tested, "example.com/bundle.json", err_td2, sid, bundle_source);
    ck_assert_int_eq(err, ERROR3);

    string_t err_id = "https://not.a.spiffe.id/wrong";
    err = spiffebundle_Endpoint_Config_HTTPS_SPIFFE(
        tested, "example.com/bundle.json", td, err_id, bundle_source);
    ck_assert_int_eq(err, ERROR5);

    err = spiffebundle_Endpoint_Config_HTTPS_SPIFFE(
        tested, "example.com/bundle.json", td, sid, NULL);
    ck_assert_int_eq(err, ERROR6);

    err = spiffebundle_Endpoint_Config_HTTPS_SPIFFE(
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

    err = spiffebundle_Endpoint_Config_HTTPS_WEB(
        NULL, "example.com/bundle.json", td);
    ck_assert_int_eq(err, ERROR1);

    err = spiffebundle_Endpoint_Config_HTTPS_WEB(tested, NULL, td);
    ck_assert_int_eq(err, ERROR2);

    err = spiffebundle_Endpoint_Config_HTTPS_WEB(tested, "not a URL", td);
    ck_assert_int_eq(err, ERROR2);

    spiffeid_TrustDomain err_td = { NULL };
    err = spiffebundle_Endpoint_Config_HTTPS_WEB(
        tested, "example.com/bundle.json", err_td);
    ck_assert_int_eq(err, ERROR3);
    spiffeid_TrustDomain err_td2 = { "not_a_td://NU,,LL" };
    err = spiffebundle_Endpoint_Config_HTTPS_WEB(
        tested, "example.com/bundle.json", err_td2);
    ck_assert_int_eq(err, ERROR3);

    err = spiffebundle_Endpoint_Config_HTTPS_WEB(
        tested, "example.com/bundle.json", td);
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
    ck_assert_uint_eq(err, ERROR1);

    spiffeid_TrustDomain err_td = { NULL };
    end_bundle
        = spiffebundle_Endpoint_GetBundleForTrustDomain(tested, err_td, &err);
    ck_assert_uint_eq(err, ERROR2);

    tested->bundle_source = NULL;
    end_bundle
        = spiffebundle_Endpoint_GetBundleForTrustDomain(tested, td, &err);
    ck_assert_uint_eq(err, ERROR3);

    tested->bundle_source = source;
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
    spiffebundle_Endpoint *tested = spiffebundle_Endpoint_New();
    err_t err;
    spiffeid_TrustDomain td = { string_new("localhost") };
    spiffebundle_Bundle *bundle
        = spiffebundle_Load(td, "./resources/jwks_valid_2.json", &err);
    
    ck_assert_uint_eq(err, NO_ERROR);
    err = spiffebundle_Endpoint_Config_HTTPS_WEB(
        tested, "https://localhost", td);
    
    ck_assert_int_eq(err,NO_ERROR);
    tested->curl_handle = curl_easy_init();

    //get certs for localhost
    curl_easy_setopt(tested->curl_handle, CURLOPT_CAINFO, "./resources/localhost.crt");


    err = spiffebundle_Endpoint_Fetch(tested);
    ck_assert_ptr_ne(tested->bundle_source,NULL);

    ck_assert(
        spiffebundle_Bundle_Equal(
            bundle,
            spiffebundle_Endpoint_GetBundleForTrustDomain(tested,td,&err)
        )
    );
    ck_assert_int_eq(err,NO_ERROR);

    bundle
        = spiffebundle_Load(td, "./resources/jwks_valid_1.json", &err);
    
    ck_assert(
        !spiffebundle_Bundle_Equal(
            bundle,
            spiffebundle_Endpoint_GetBundleForTrustDomain(tested,td,&err)
        )
    );
    ck_assert_uint_eq(err, NO_ERROR);
    spiffeid_TrustDomain_Free(&td);
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
    // tcase_add_test(tc_core, test_federation_Endpoint_fetch_SPIFFE);
    
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
