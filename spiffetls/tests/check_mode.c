#include <check.h>
#include "spiffetls/src/mode.h"

START_TEST(test_spiffetls_TLSClient)
{
    tlsconfig_Authorizer *authorizer = tlsconfig_AuthorizeAny();
    spiffetls_DialMode *mode = spiffetls_TLSClient(authorizer);

    ck_assert_ptr_ne(mode, NULL);
    ck_assert_uint_eq(mode->mode, TLS_CLIENT_MODE);
    ck_assert_ptr_eq(mode->authorizer, authorizer);

    tlsconfig_Authorizer_Free(authorizer);
    spiffetls_DialMode_Free(mode);
}
END_TEST

START_TEST(test_spiffetls_TLSClientWithSource)
{
    tlsconfig_Authorizer *authorizer = tlsconfig_AuthorizeAny();
    err_t err;
    workloadapi_X509Source *source = workloadapi_NewX509Source(NULL, &err);
    ck_assert_uint_eq(err, NO_ERROR);
    spiffetls_DialMode *mode = spiffetls_TLSClientWithSource(authorizer, source);

    ck_assert_ptr_ne(mode, NULL);
    ck_assert_uint_eq(mode->mode, TLS_CLIENT_MODE);
    ck_assert_ptr_eq(mode->authorizer, authorizer);
    ck_assert_ptr_eq(mode->source, source);

    tlsconfig_Authorizer_Free(authorizer);
    workloadapi_X509Source_Free(source);
    spiffetls_DialMode_Free(mode);
}
END_TEST

START_TEST(test_spiffetls_TLSClientWithRawConfig)
{
    tlsconfig_Authorizer *authorizer = tlsconfig_AuthorizeAny();
    x509bundle_Source *bundle = NULL;
    spiffetls_DialMode *mode = spiffetls_TLSClientWithRawConfig(authorizer, bundle);

    ck_assert_ptr_ne(mode, NULL);
    ck_assert_uint_eq(mode->mode, TLS_CLIENT_MODE);
    ck_assert_ptr_eq(mode->authorizer, authorizer);
    ck_assert_ptr_eq(mode->bundle, bundle);
    ck_assert(mode->unneeded_source);

    tlsconfig_Authorizer_Free(authorizer);
    x509bundle_Source_Free(bundle);
    spiffetls_DialMode_Free(mode);
}
END_TEST

START_TEST(test_spiffetls_MTLSClient)
{
    tlsconfig_Authorizer *authorizer = tlsconfig_AuthorizeAny();
    spiffetls_DialMode *mode = spiffetls_MTLSClient(authorizer);

    ck_assert_ptr_ne(mode, NULL);
    ck_assert_uint_eq(mode->mode, MTLS_CLIENT_MODE);
    ck_assert_ptr_eq(mode->authorizer, authorizer);

    tlsconfig_Authorizer_Free(authorizer);
    spiffetls_DialMode_Free(mode);
}
END_TEST

START_TEST(test_spiffetls_MTLSClientWithSource)
{
    tlsconfig_Authorizer *authorizer = tlsconfig_AuthorizeAny();
    err_t err;
    workloadapi_X509Source *source = workloadapi_NewX509Source(NULL, &err);
    ck_assert_uint_eq(err, NO_ERROR);
    spiffetls_DialMode *mode = spiffetls_MTLSClientWithSource(authorizer, source);

    ck_assert_ptr_ne(mode, NULL);
    ck_assert_uint_eq(mode->mode, MTLS_CLIENT_MODE);
    ck_assert_ptr_eq(mode->authorizer, authorizer);
    ck_assert_ptr_eq(mode->source, source);

    tlsconfig_Authorizer_Free(authorizer);
    workloadapi_X509Source_Free(source);
    spiffetls_DialMode_Free(mode);
}
END_TEST

START_TEST(test_spiffetls_MTLSClientWithRawConfig)
{
    tlsconfig_Authorizer *authorizer = tlsconfig_AuthorizeAny();
    x509bundle_Source *bundle = NULL;
    x509svid_Source *svid = NULL;
    spiffetls_DialMode *mode = spiffetls_MTLSClientWithRawConfig(authorizer, bundle, svid);

    ck_assert_ptr_ne(mode, NULL);
    ck_assert_uint_eq(mode->mode, MTLS_CLIENT_MODE);
    ck_assert_ptr_eq(mode->authorizer, authorizer);
    ck_assert_ptr_eq(mode->bundle, bundle);
    ck_assert(mode->unneeded_source);
    ck_assert_ptr_eq(mode->svid, svid);

    tlsconfig_Authorizer_Free(authorizer);
    x509bundle_Source_Free(bundle);
    x509svid_Source_Free(svid);
    spiffetls_DialMode_Free(mode);
}
END_TEST

START_TEST(test_spiffetls_MTLSWebClient)
{
    x509util_CertPool *roots = NULL;
    spiffetls_DialMode *mode = spiffetls_MTLSWebClient(roots);

    ck_assert_ptr_ne(mode, NULL);
    ck_assert_uint_eq(mode->mode, MTLS_WEBCLIENT_MODE);
    ck_assert_ptr_eq(mode->roots, roots);

    x509util_CertPool_Free(roots);
    spiffetls_DialMode_Free(mode);
}
END_TEST

START_TEST(test_spiffetls_MTLSWebClientWithSource)
{
    x509util_CertPool *roots = NULL;
    err_t err;
    workloadapi_X509Source *source = workloadapi_NewX509Source(NULL, &err);
    ck_assert_uint_eq(err, NO_ERROR);
    spiffetls_DialMode *mode = spiffetls_MTLSWebClientWithSource(roots, source);

    ck_assert_ptr_ne(mode, NULL);
    ck_assert_uint_eq(mode->mode, MTLS_WEBCLIENT_MODE);
    ck_assert_ptr_eq(mode->roots, roots);
    ck_assert_ptr_eq(mode->source, source);

    x509util_CertPool_Free(roots);
    workloadapi_X509Source_Free(source);
    spiffetls_DialMode_Free(mode);
}
END_TEST

START_TEST(test_spiffetls_MTLSWebClientWithRawConfig)
{
    x509util_CertPool *roots = NULL;
    x509svid_Source *svid = NULL;
    spiffetls_DialMode *mode = spiffetls_MTLSWebClientWithRawConfig(roots, svid);

    ck_assert_ptr_ne(mode, NULL);
    ck_assert_uint_eq(mode->mode, MTLS_WEBCLIENT_MODE);
    ck_assert_ptr_eq(mode->roots, roots);
    ck_assert(mode->unneeded_source);
    ck_assert_ptr_eq(mode->svid, svid);

    x509util_CertPool_Free(roots);
    x509svid_Source_Free(svid);
    spiffetls_DialMode_Free(mode);
}
END_TEST

Suite *mode_suite(void)
{
    Suite *s = suite_create("mode");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_spiffetls_TLSClient);
    tcase_add_test(tc_core, test_spiffetls_TLSClientWithSource);
    tcase_add_test(tc_core, test_spiffetls_TLSClientWithRawConfig);
    tcase_add_test(tc_core, test_spiffetls_MTLSClient);
    tcase_add_test(tc_core, test_spiffetls_MTLSClientWithSource);
    tcase_add_test(tc_core, test_spiffetls_MTLSClientWithRawConfig);
    tcase_add_test(tc_core, test_spiffetls_MTLSWebClient);
    tcase_add_test(tc_core, test_spiffetls_MTLSWebClientWithSource);
    tcase_add_test(tc_core, test_spiffetls_MTLSWebClientWithRawConfig);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    Suite *s = mode_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}