#include "spiffetls/src/listen.h"
#include <check.h>
#include <threads.h>
#include <unistd.h>

int call_client(void *unused)
{
    sleep(2);
    system("./tls_client &");
    return 0;
}

START_TEST(test_spiffetls_ListenWithMode)
{
    err_t err;
    x509svid_SVID *svid
        = x509svid_Load("./resources/good-leaf-and-intermediate.pem",
                        "./resources/key-pkcs8-ecdsa.pem", &err);
    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(svid, NULL);
    x509svid_Source *svid_src = x509svid_SourceFromSVID(svid);

    spiffetls_ListenMode *mode = spiffetls_TLSServerWithRawConfig(svid_src);

    thrd_t thread;
    thrd_create(&thread, call_client, NULL);

    spiffetls_listenConfig config
        = { .base_TLS_conf = NULL, .listener_fd = 0 };
    int serverfd;
    SSL *conn = spiffetls_ListenWithMode((in_port_t) 4433,
                                         /*127.0.0.1*/ (in_addr_t) 0x7F000001,
                                         mode, &config, &serverfd, &err);
    
    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(conn, NULL);

    const int len = 1024;
    char buffer[len];
    const int ret = SSL_read(conn, buffer, len);

    if(ret > 0) {
        printf("Client sent: %s\n", buffer);
    }

    spiffetls_ListenMode_Free(mode);

    const int fd = SSL_get_fd(conn);
    SSL_shutdown(conn);
    SSL_free(conn);
    close(fd);
    close(serverfd);
}
END_TEST

Suite *listen_suite(void)
{
    Suite *s = suite_create("listen");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_spiffetls_ListenWithMode);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    Suite *s = listen_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
