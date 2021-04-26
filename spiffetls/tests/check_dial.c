#include "spiffetls/src/dial.h"
#include <check.h>
#include <unistd.h>

START_TEST(test_spiffetls_DialWithMode)
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

    spiffetls_dialConfig config = { .base_TLS_conf = NULL, .dialer_fd = -1 };

    SSL *conn = spiffetls_DialWithMode((in_port_t) 4433,
                                       /*127.0.0.1*/ (in_addr_t) 0x7F000001,
                                       mode, &config, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(conn, NULL);

    spiffeid_TrustDomain_Free(&td);
    spiffetls_DialMode_Free(mode);

    const int fd = SSL_get_fd(conn);
    SSL_shutdown(conn);
    SSL_free(conn);
    close(fd);
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

    system("./tls_server &");
    sleep(1);

    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
