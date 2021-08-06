#include "c-spiffe/spiffetls/dial.h"
#include <check.h>
#include <unistd.h>

void test_TLSClientWithRawConfig(void)
{
    spiffeid_TrustDomain td = { string_new("example.org") };
    tlsconfig_Authorizer *authorizer = tlsconfig_AuthorizeMemberOf(td);
    err_t err;
    x509bundle_Bundle *bundle = x509bundle_Load(
        td, "resources/good-leaf-and-intermediate.pem", &err);

    ck_assert_uint_eq(err, NO_ERROR);

    x509bundle_Source *bundle_src = x509bundle_SourceFromBundle(bundle);

    spiffetls_DialMode *mode
        = spiffetls_TLSClientWithRawConfig(authorizer, bundle_src);

    spiffetls_dialConfig config
        = { .base_TLS_conf = NULL, .dialer_fd = /*invalid dialer*/ -1 };

    SSL *conn = spiffetls_DialWithMode((in_port_t) 40001,
                                       /*127.0.0.1*/ (in_addr_t) 0x7F000001,
                                       mode, &config, &err);
    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert_ptr_eq(conn, NULL);

    spiffeid_TrustDomain_Free(&td);
    spiffetls_DialMode_Free(mode);
}

void test_MTLSClient(void)
{
    spiffeid_TrustDomain td = { string_new("example.org") };
    tlsconfig_Authorizer *authorizer = tlsconfig_AuthorizeMemberOf(td);

    spiffetls_DialMode *mode = spiffetls_MTLSClient(authorizer);

    spiffetls_dialConfig config
        = { .base_TLS_conf = NULL, .dialer_fd = /*invalid dialer*/ -1 };

    err_t err;
    SSL *conn = spiffetls_DialWithMode((in_port_t) 40002,
                                       /*127.0.0.1*/ (in_addr_t) 0x7F000001,
                                       mode, &config, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(conn, NULL);

    spiffeid_TrustDomain_Free(&td);
    spiffetls_DialMode_Free(mode);
}

void test_MTLSWebClient(void)
{
    spiffeid_TrustDomain td = { string_new("example.org") };
    tlsconfig_Authorizer *authorizer = tlsconfig_AuthorizeMemberOf(td);
    err_t err;

    spiffetls_DialMode *mode = spiffetls_MTLSWebClient(NULL);

    spiffetls_dialConfig config
        = { .base_TLS_conf = NULL, .dialer_fd = /*invalid dialer*/ -1 };
    SSL *conn = spiffetls_DialWithMode((in_port_t) 40003,
                                       /*127.0.0.1*/ (in_addr_t) 0x7F000001,
                                       mode, &config, &err);

    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert_ptr_eq(conn, NULL);

    spiffeid_TrustDomain_Free(&td);
    spiffetls_DialMode_Free(mode);
}

START_TEST(test_spiffetls_DialWithMode)
{
    system("./tls_server 40001 &");
    sleep(1);
    test_TLSClientWithRawConfig();

    system("./tls_server 40002 &");
    sleep(1);
    test_MTLSClient();

    system("./tls_server 40003 &");
    sleep(1);
    test_MTLSWebClient();
}
END_TEST

Suite *dial_suite(void)
{
    Suite *s = suite_create("dial");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_spiffetls_DialWithMode);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    Suite *s = dial_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
