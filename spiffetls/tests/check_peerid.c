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

#include "c-spiffe/spiffetls/dial.h"
#include "c-spiffe/spiffetls/mode.h"
#include "c-spiffe/spiffetls/peerid.h"
#include "c-spiffe/spiffetls/tlsconfig/config.h"
#include <check.h>
#include <stdio.h>
#include <unistd.h>

START_TEST(test_spiffetls_PeerIDFromConn)
{
    /* Hot path */
    system("./tls_server 40004 resources/good-leaf-only.pem "
           "resources/key-pkcs8-rsa.pem &");
    sleep(1);

    spiffeid_TrustDomain td = { string_new("example.org") };
    tlsconfig_Authorizer *authorizer = tlsconfig_AuthorizeMemberOf(td);
    spiffetls_DialMode *mode = spiffetls_TLSClient(authorizer);
    spiffetls_dialConfig config = { .base_TLS_conf = NULL, .dialer_fd = -1 };

    err_t err;
    SSL *conn = spiffetls_DialWithMode((in_port_t) 40004,
                                       /*127.0.0.1*/ (in_addr_t) 0x7F000001,
                                       mode, &config, &err);

    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert_ptr_eq(conn, NULL);

    /* certificate with no spiffe ID */
    system("./tls_server 40005 &");
    sleep(1);

    conn = spiffetls_DialWithMode((in_port_t) 40005,
                                  /*127.0.0.1*/ (in_addr_t) 0x7F000001, mode,
                                  &config, &err);
    spiffeid_ID id = spiffetls_PeerIDFromConn(conn, &err);

    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert_ptr_eq(id.td.name, NULL);
    ck_assert_ptr_eq(id.path, NULL);

    spiffeid_TrustDomain_Free(&td);
    spiffetls_DialMode_Free(mode);

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
