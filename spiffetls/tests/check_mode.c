#include "c-spiffe/spiffetls/mode.h"
#include <check.h>

START_TEST(test_spiffetls_TLSClient)
{
    tlsconfig_Authorizer *authorizer = tlsconfig_AuthorizeAny();
    spiffetls_DialMode *mode = spiffetls_TLSClient(authorizer);

    ck_assert_ptr_ne(mode, NULL);
    ck_assert_uint_eq(mode->mode, TLS_CLIENT_MODE);
    ck_assert_ptr_eq(mode->authorizer, authorizer);

    spiffetls_DialMode_Free(mode);
}
END_TEST

START_TEST(test_spiffetls_TLSClientWithSource)
{
    tlsconfig_Authorizer *authorizer = tlsconfig_AuthorizeAny();
    err_t err;
    workloadapi_X509Source *source = workloadapi_NewX509Source(NULL, &err);
    ck_assert_uint_eq(err, NO_ERROR);
    spiffetls_DialMode *mode
        = spiffetls_TLSClientWithSource(authorizer, source);

    ck_assert_ptr_ne(mode, NULL);
    ck_assert_uint_eq(mode->mode, TLS_CLIENT_MODE);
    ck_assert_ptr_eq(mode->authorizer, authorizer);
    ck_assert_ptr_eq(mode->source, source);

    spiffetls_DialMode_Free(mode);
}
END_TEST

START_TEST(test_spiffetls_TLSClientWithRawConfig)
{
    tlsconfig_Authorizer *authorizer = tlsconfig_AuthorizeAny();
    x509bundle_Source *bundle = NULL;
    spiffetls_DialMode *mode
        = spiffetls_TLSClientWithRawConfig(authorizer, bundle);

    ck_assert_ptr_ne(mode, NULL);
    ck_assert_uint_eq(mode->mode, TLS_CLIENT_MODE);
    ck_assert_ptr_eq(mode->authorizer, authorizer);
    ck_assert_ptr_eq(mode->bundle, bundle);
    ck_assert(mode->unneeded_source);

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

    spiffetls_DialMode_Free(mode);
}
END_TEST

START_TEST(test_spiffetls_MTLSClientWithSource)
{
    tlsconfig_Authorizer *authorizer = tlsconfig_AuthorizeAny();
    err_t err;
    workloadapi_X509Source *source = workloadapi_NewX509Source(NULL, &err);
    ck_assert_uint_eq(err, NO_ERROR);
    spiffetls_DialMode *mode
        = spiffetls_MTLSClientWithSource(authorizer, source);

    ck_assert_ptr_ne(mode, NULL);
    ck_assert_uint_eq(mode->mode, MTLS_CLIENT_MODE);
    ck_assert_ptr_eq(mode->authorizer, authorizer);
    ck_assert_ptr_eq(mode->source, source);

    spiffetls_DialMode_Free(mode);
}
END_TEST

START_TEST(test_spiffetls_MTLSClientWithRawConfig)
{
    tlsconfig_Authorizer *authorizer = tlsconfig_AuthorizeAny();
    x509bundle_Source *bundle = NULL;
    x509svid_Source *svid = NULL;
    spiffetls_DialMode *mode
        = spiffetls_MTLSClientWithRawConfig(authorizer, bundle, svid);

    ck_assert_ptr_ne(mode, NULL);
    ck_assert_uint_eq(mode->mode, MTLS_CLIENT_MODE);
    ck_assert_ptr_eq(mode->authorizer, authorizer);
    ck_assert_ptr_eq(mode->bundle, bundle);
    ck_assert(mode->unneeded_source);
    ck_assert_ptr_eq(mode->svid, svid);

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

    spiffetls_DialMode_Free(mode);
}
END_TEST

START_TEST(test_spiffetls_MTLSWebClientWithSource)
{
    x509util_CertPool *roots = NULL;
    err_t err;
    workloadapi_X509Source *source = workloadapi_NewX509Source(NULL, &err);
    ck_assert_uint_eq(err, NO_ERROR);
    spiffetls_DialMode *mode
        = spiffetls_MTLSWebClientWithSource(roots, source);

    ck_assert_ptr_ne(mode, NULL);
    ck_assert_uint_eq(mode->mode, MTLS_WEBCLIENT_MODE);
    ck_assert_ptr_eq(mode->roots, roots);
    ck_assert_ptr_eq(mode->source, source);

    spiffetls_DialMode_Free(mode);
}
END_TEST

START_TEST(test_spiffetls_MTLSWebClientWithRawConfig)
{
    x509util_CertPool *roots = NULL;
    x509svid_Source *svid = NULL;
    spiffetls_DialMode *mode
        = spiffetls_MTLSWebClientWithRawConfig(roots, svid);

    ck_assert_ptr_ne(mode, NULL);
    ck_assert_uint_eq(mode->mode, MTLS_WEBCLIENT_MODE);
    ck_assert_ptr_eq(mode->roots, roots);
    ck_assert(mode->unneeded_source);
    ck_assert_ptr_eq(mode->svid, svid);

    spiffetls_DialMode_Free(mode);
}
END_TEST

START_TEST(test_spiffetls_TLSServer)
{
    spiffetls_ListenMode *mode = spiffetls_TLSServer();

    ck_assert_ptr_ne(mode, NULL);
    ck_assert_uint_eq(mode->mode, TLS_SERVER_MODE);

    spiffetls_ListenMode_Free(mode);
}
END_TEST

START_TEST(test_spiffetls_TLSServerWithSource)
{
    err_t err;
    workloadapi_X509Source *source = workloadapi_NewX509Source(NULL, &err);
    ck_assert_uint_eq(err, NO_ERROR);
    spiffetls_ListenMode *mode = spiffetls_TLSServerWithSource(source);

    ck_assert_ptr_ne(mode, NULL);
    ck_assert_uint_eq(mode->mode, TLS_SERVER_MODE);
    ck_assert_ptr_eq(mode->source, source);

    spiffetls_ListenMode_Free(mode);
}
END_TEST

START_TEST(test_spiffetls_TLSServerWithRawConfig)
{
    x509svid_Source *svid = NULL;
    spiffetls_ListenMode *mode = spiffetls_TLSServerWithRawConfig(svid);

    ck_assert_ptr_ne(mode, NULL);
    ck_assert_uint_eq(mode->mode, TLS_SERVER_MODE);
    ck_assert_ptr_eq(mode->svid, svid);

    spiffetls_ListenMode_Free(mode);
}
END_TEST

START_TEST(test_spiffetls_MTLSServer)
{
    tlsconfig_Authorizer *authorizer = tlsconfig_AuthorizeAny();
    spiffetls_ListenMode *mode = spiffetls_MTLSServer(authorizer);

    ck_assert_ptr_ne(mode, NULL);
    ck_assert_uint_eq(mode->mode, MTLS_SERVER_MODE);
    ck_assert_ptr_eq(mode->authorizer, authorizer);

    spiffetls_ListenMode_Free(mode);
}
END_TEST

START_TEST(test_spiffetls_MTLSServerWithSource)
{
    err_t err;
    tlsconfig_Authorizer *authorizer = tlsconfig_AuthorizeAny();
    workloadapi_X509Source *source = workloadapi_NewX509Source(NULL, &err);
    ck_assert_uint_eq(err, NO_ERROR);
    spiffetls_ListenMode *mode
        = spiffetls_MTLSServerWithSource(authorizer, source);

    ck_assert_ptr_ne(mode, NULL);
    ck_assert_uint_eq(mode->mode, MTLS_SERVER_MODE);
    ck_assert_ptr_eq(mode->authorizer, authorizer);
    ck_assert_ptr_eq(mode->source, source);

    spiffetls_ListenMode_Free(mode);
}
END_TEST

START_TEST(test_spiffetls_MTLSServerWithRawConfig)
{
    err_t err;
    tlsconfig_Authorizer *authorizer = tlsconfig_AuthorizeAny();
    x509svid_Source *svid = NULL;
    x509bundle_Source *bundle = NULL;
    spiffetls_ListenMode *mode
        = spiffetls_MTLSServerWithRawConfig(authorizer, svid, bundle);

    ck_assert_ptr_ne(mode, NULL);
    ck_assert_uint_eq(mode->mode, MTLS_SERVER_MODE);
    ck_assert_ptr_eq(mode->authorizer, authorizer);
    ck_assert_ptr_eq(mode->svid, svid);
    ck_assert_ptr_eq(mode->bundle, bundle);

    spiffetls_ListenMode_Free(mode);
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
    tcase_add_test(tc_core, test_spiffetls_TLSServer);
    tcase_add_test(tc_core, test_spiffetls_TLSServerWithSource);
    tcase_add_test(tc_core, test_spiffetls_TLSServerWithRawConfig);
    tcase_add_test(tc_core, test_spiffetls_MTLSServer);
    tcase_add_test(tc_core, test_spiffetls_MTLSServerWithSource);
    tcase_add_test(tc_core, test_spiffetls_MTLSServerWithRawConfig);

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
