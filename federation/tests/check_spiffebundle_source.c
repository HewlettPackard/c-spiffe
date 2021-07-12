#include "c-spiffe/bundle/spiffebundle/source.h"
#include <check.h>

START_TEST(test_spiffebundle_SourceFromBundle)
{
    err_t err;
    spiffeid_TrustDomain td = { string_new("example.com") };
    spiffebundle_Bundle *bundle
        = spiffebundle_Load(td, "./resources/jwks_valid_2.json", &err);

    ck_assert_uint_eq(err, NO_ERROR);

    spiffebundle_Source *source = spiffebundle_SourceFromBundle(NULL);

    ck_assert_ptr_eq(source, NULL);

    source = spiffebundle_SourceFromBundle(bundle);

    ck_assert_ptr_ne(source, NULL);

    spiffeid_TrustDomain_Free(&td);
    spiffebundle_Source_Free(source);
}
END_TEST

START_TEST(test_spiffebundle_SourceFromSet)
{
    err_t err;
    spiffeid_TrustDomain td = { string_new("example.com") };
    spiffebundle_Bundle *bundle
        = spiffebundle_Load(td, "./resources/jwks_valid_2.json", &err);

    ck_assert_uint_eq(err, NO_ERROR);

    spiffebundle_Set *set = spiffebundle_NewSet(1, bundle);
    spiffebundle_Source *source = spiffebundle_SourceFromSet(NULL);
    ck_assert_ptr_eq(source, NULL);

    source = spiffebundle_SourceFromSet(set);
    ck_assert_ptr_ne(source, NULL);

    spiffeid_TrustDomain_Free(&td);
    spiffebundle_Source_Free(source);
}
END_TEST

START_TEST(test_spiffebundle_SourceFromEndpoint)
{
    err_t err;
    spiffeid_TrustDomain td = { string_new("example.com") };
    spiffebundle_Bundle *bundle
        = spiffebundle_Load(td, "./resources/jwks_valid_2.json", &err);

    ck_assert_uint_eq(err, NO_ERROR);

    spiffebundle_Set *set = spiffebundle_NewSet(1, bundle);
    spiffebundle_Source *source = spiffebundle_SourceFromSet(NULL);
    ck_assert_ptr_eq(source, NULL);

    source = spiffebundle_SourceFromSet(set);
    ck_assert_ptr_ne(source, NULL);

    spiffebundle_Endpoint *endpoint = spiffebundle_Endpoint_New();
    endpoint->source = source;

    spiffebundle_Source *end_source = spiffebundle_SourceFromEndpoint(NULL);
    ck_assert_ptr_eq(end_source, NULL);

    end_source = spiffebundle_SourceFromEndpoint(endpoint);
    ck_assert_ptr_ne(end_source, NULL);

    spiffeid_TrustDomain_Free(&td);
    spiffebundle_Source_Free(end_source);
    spiffebundle_Source_Free(source);
}
END_TEST

START_TEST(test_spiffebundle_Source_GetspiffeBundleForTrustDomain)
{
    err_t err;
    spiffeid_TrustDomain td = { string_new("example.com") };
    spiffebundle_Bundle *bundle
        = spiffebundle_Load(td, "./resources/jwks_valid_2.json", &err);

    ck_assert_uint_eq(err, NO_ERROR);

    spiffebundle_Source *source = spiffebundle_SourceFromBundle(bundle);
    spiffebundle_Bundle *ret_bundle
        = spiffebundle_Source_GetSpiffeBundleForTrustDomain(source, td, &err);
    ck_assert_ptr_ne(ret_bundle, NULL);
    ck_assert_int_eq(err, NO_ERROR);
    ck_assert_ptr_eq(ret_bundle, bundle);
    spiffebundle_Source_Free(source);

    bundle = spiffebundle_Load(td, "./resources/jwks_valid_2.json", &err);
    ck_assert_uint_eq(err, NO_ERROR);

    spiffebundle_Set *set = spiffebundle_NewSet(1, bundle);
    source = spiffebundle_SourceFromSet(set);
    ck_assert_ptr_ne(source, NULL);
    ret_bundle
        = spiffebundle_Source_GetSpiffeBundleForTrustDomain(source, td, &err);

    ck_assert_ptr_ne(ret_bundle, NULL);
    ck_assert_int_eq(err, NO_ERROR);
    ck_assert_ptr_eq(ret_bundle, bundle);

    spiffebundle_Source_Free(source);

    bundle = spiffebundle_Load(td, "./resources/jwks_valid_2.json", &err);
    ck_assert_uint_eq(err, NO_ERROR);
    set = spiffebundle_NewSet(1, bundle);
    source = spiffebundle_SourceFromSet(set);

    spiffebundle_Endpoint *endpoint = spiffebundle_Endpoint_New();
    endpoint->source = source;

    spiffebundle_Source *end_source
        = spiffebundle_SourceFromEndpoint(endpoint);
    ck_assert_ptr_ne(end_source, NULL);

    ret_bundle
        = spiffebundle_Source_GetSpiffeBundleForTrustDomain(end_source, td, &err);
    ck_assert_ptr_ne(ret_bundle, NULL);
    ck_assert_int_eq(err, NO_ERROR);
    ck_assert_ptr_eq(ret_bundle, bundle);

    spiffebundle_Source_Free(end_source);
    spiffebundle_Source_Free(source);

    ret_bundle
        = spiffebundle_Source_GetSpiffeBundleForTrustDomain(NULL, td, &err);
    ck_assert_ptr_eq(ret_bundle, NULL);
    ck_assert_int_eq(err, ERR_GET);
    
    spiffeid_TrustDomain_Free(&td);
        
}
END_TEST

Suite *bundlesource_suite(void)
{
    Suite *s = suite_create("spiffebundle source");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_spiffebundle_SourceFromSet);
    tcase_add_test(tc_core, test_spiffebundle_SourceFromBundle);
    tcase_add_test(tc_core, test_spiffebundle_SourceFromEndpoint);
    tcase_add_test(tc_core,
                   test_spiffebundle_Source_GetspiffeBundleForTrustDomain);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    Suite *s = bundlesource_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
