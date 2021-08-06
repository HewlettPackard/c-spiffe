#include "c-spiffe/bundle/x509bundle/source.h"
#include "c-spiffe/bundle/jwtbundle/source.h"
#include <check.h>

START_TEST(test_x509bundle_SourceFromSet)
{
    err_t err;
    spiffeid_TrustDomain td = { string_new("example1.com") };
    x509bundle_Bundle *bundle
        = x509bundle_Load(td, "./resources/certs.pem", &err);

    ck_assert_uint_eq(err, NO_ERROR);

    x509bundle_Set *set = x509bundle_NewSet(1, bundle);
    x509bundle_Source *source = x509bundle_SourceFromSet(set);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(source, NULL);

    spiffeid_TrustDomain_Free(&td);
    x509bundle_Source_Free(source);
}
END_TEST

START_TEST(test_x509bundle_Source_GetX509BundleForTrustDomain)
{
    err_t err;
    spiffeid_TrustDomain td = { string_new("example1.com") };
    x509bundle_Bundle *bundle
        = x509bundle_Load(td, "./resources/certs.pem", &err);

    ck_assert_uint_eq(err, NO_ERROR);

    x509bundle_Set *set = x509bundle_NewSet(1, bundle);
    x509bundle_Source *source = x509bundle_SourceFromSet(set);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(source, NULL);

    bundle = x509bundle_Source_GetX509BundleForTrustDomain(source, td, &err);

    spiffeid_TrustDomain_Free(&td);
    x509bundle_Source_Free(source);
}
END_TEST

START_TEST(test_jwtbundle_SourceFromSet)
{
    err_t err;
    spiffeid_TrustDomain td = { string_new("example1.com") };
    jwtbundle_Bundle *bundle
        = jwtbundle_Load(td, "./resources/jwk_keys.json", &err);

    ck_assert_uint_eq(err, NO_ERROR);

    jwtbundle_Set *set = jwtbundle_NewSet(1, bundle);
    jwtbundle_Source *source = jwtbundle_SourceFromSet(set);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(source, NULL);

    spiffeid_TrustDomain_Free(&td);
    jwtbundle_Source_Free(source);
}
END_TEST

START_TEST(test_jwtbundle_SourceFromSource)
{

}
END_TEST

Suite *bundlesource_suite(void)
{
    Suite *s = suite_create("bundle source");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_x509bundle_SourceFromSet);
    tcase_add_test(tc_core, test_x509bundle_Source_GetX509BundleForTrustDomain);
    tcase_add_test(tc_core, test_jwtbundle_SourceFromSet);

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
