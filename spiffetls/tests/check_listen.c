/**
 *
 * (C) Copyright 2020-2021 Hewlett Packard Enterprise Development LP
 *
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 */

#include "c-spiffe/spiffetls/listen.h"
#include <check.h>
#include <unistd.h>

void *call_client(void *arg)
{
    sleep(1);
    const char *port = arg;
    string_t run = string_new("./tls_client ");
    run = string_push(run, port);
    run = string_push(run, " &");
    system(run);
    arrfree(run);
    pthread_exit(NULL);
    return NULL;
}

void test_TLSServerWithRawConfig(void)
{
    err_t err;
    x509svid_SVID *svid
        = x509svid_Load("./resources/good-leaf-and-intermediate.pem",
                        "./resources/key-pkcs8-ecdsa.pem", &err);
    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(svid, NULL);
    x509svid_Source *svid_src = x509svid_SourceFromSVID(svid);

    spiffetls_ListenMode *mode = spiffetls_TLSServerWithRawConfig(svid_src);

    pthread_t thread;
    pthread_create(&thread, NULL, call_client, "20001");

    spiffetls_listenConfig config
        = { .base_TLS_conf = NULL, .listener_fd = -1 };
    int serverfd;
    SSL *conn = spiffetls_ListenWithMode((in_port_t) 20001, mode, &config,
                                         &serverfd, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(conn, NULL);

    const int len = 1024;
    char buffer[len];
    const int ret = SSL_read(conn, buffer, len);
    buffer[ret] = 0;
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

void test_MTLSServerWithRawConfig(void)
{
    spiffeid_TrustDomain td = { string_new("example.org") };
    tlsconfig_Authorizer *authorizer = tlsconfig_AuthorizeMemberOf(td);

    spiffetls_ListenMode *mode = spiffetls_MTLSServer(authorizer);

    pthread_t thread;
    pthread_create(&thread, NULL, call_client, "20002");

    spiffetls_listenConfig config
        = { .base_TLS_conf = NULL, .listener_fd = -1 };
    int serverfd;
    err_t err;
    SSL *conn = spiffetls_ListenWithMode((in_port_t) 20002, mode, &config,
                                         &serverfd, &err);

    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert_ptr_eq(conn, NULL);

    spiffeid_TrustDomain_Free(&td);
    spiffetls_ListenMode_Free(mode);
}

// precondition: valid x509 svid, available port and thread running client
// postcondition: valid TLS connection able to read from client
START_TEST(test_spiffetls_ListenWithMode)
{
    test_TLSServerWithRawConfig();

    test_MTLSServerWithRawConfig();
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
