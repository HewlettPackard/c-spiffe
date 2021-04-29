#include "spiffetls/src/dial.h"
#include "spiffetls/src/mode.h"
#include "spiffetls/src/peerid.h"
#include "spiffetls/tlsconfig/src/config.h"
#include <check.h>
#include <stdio.h>
#include <unistd.h>

START_TEST(test_spiffetls_PeerIDFromConn)
{
    /* Hot path */
    system("./tls_server resources/good-leaf-only.pem "
           "resources/key-pkcs8-rsa.pem &");
    sleep(1);

    spiffeid_TrustDomain td = { string_new("example.org") };
    tlsconfig_Authorizer *authorizer = tlsconfig_AuthorizeMemberOf(td);
    spiffetls_DialMode *mode = spiffetls_TLSClient(authorizer);
    spiffetls_dialConfig config = { .base_TLS_conf = NULL, .dialer_fd = -1 };

    err_t err;
    SSL *conn = spiffetls_DialWithMode((in_port_t) 4433,
                                       /*127.0.0.1*/ (in_addr_t) 0x7F000001,
                                       mode, &config, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(conn, NULL);

    spiffeid_ID id = spiffetls_PeerIDFromConn(conn, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(id.td.name, NULL);
    ck_assert_ptr_ne(id.path, NULL);

    // spiffeid_TrustDomain_Free(&td);
    // spiffetls_DialMode_Free(mode);
    int sock_fd = SSL_get_fd(conn);
    SSL_shutdown(conn);
    SSL_free(conn);
    close(sock_fd);
    spiffeid_ID_Free(&id);

    /* certificate with no spiffe ID */
    /// TODO: create connection which returns certificate with no spiffe ID
    system("./tls_server &");
    sleep(1);

    conn = spiffetls_DialWithMode((in_port_t) 4433,
                                  /*127.0.0.1*/ (in_addr_t) 0x7F000001, mode,
                                  &config, &err);
    id = spiffetls_PeerIDFromConn(conn, &err);

    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert_ptr_eq(id.td.name, NULL);
    ck_assert_ptr_eq(id.path, NULL);

    sock_fd = SSL_get_fd(conn);
    SSL_shutdown(conn);
    SSL_free(conn);
    close(sock_fd);

    /* NULL TLS connection */
    conn = NULL;
    id = spiffetls_PeerIDFromConn(conn, &err);

    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert_ptr_eq(id.td.name, NULL);
    ck_assert_ptr_eq(id.path, NULL);
}
END_TEST

Suite *peerid_suite(void)
{
    Suite *s = suite_create("peerid");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_spiffetls_PeerIDFromConn);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    Suite *s = peerid_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
