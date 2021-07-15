#include "c-spiffe/bundle/spiffebundle.h"
#include "c-spiffe/federation/federation.h"
#include "c-spiffe/internal/pemutil.h"
#include "c-spiffe/spiffeid/spiffeid.h"
#include "c-spiffe/spiffetls/spiffetls.h"
#include "c-spiffe/utils/picohttpparser.h"
#include "c-spiffe/utils/util.h"
#include "openssl/ssl.h"
#include <check.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

START_TEST(test_spiffebundle_EndpointInfo_New_Free)
{
    spiffebundle_EndpointInfo *info = spiffebundle_EndpointInfo_New();

    ck_assert_ptr_ne(info, NULL);
    ck_assert_ptr_eq(info->server, NULL);
    ck_assert_ptr_eq(info->url, NULL);
    ck_assert_ptr_eq(info->listen_mode, NULL);
    ck_assert_ptr_eq(info->threads, NULL);

    err_t error = spiffebundle_EndpointInfo_Free(info);
    ck_assert_int_eq(error, NO_ERROR);
    error = spiffebundle_EndpointInfo_Free(NULL);
    ck_assert_int_ne(error, NO_ERROR);
}
END_TEST

START_TEST(test_spiffebundle_EndpointServer_New_Free)
{
    spiffebundle_EndpointServer *server = spiffebundle_EndpointServer_New();

    ck_assert_ptr_ne(server, NULL);
    ck_assert_ptr_ne(server->bundle_sources, NULL);
    ck_assert_ptr_ne(server->bundle_tds, NULL);
    ck_assert_ptr_ne(server->endpoints, NULL);

    err_t error = spiffebundle_EndpointServer_Free(server);
    ck_assert_int_eq(error, NO_ERROR);
    error = spiffebundle_EndpointServer_Free(NULL);
    ck_assert_int_ne(error, NO_ERROR);
}
END_TEST

START_TEST(test_spiffebundle_EndpointServer_BundleFunctions)
{
    spiffebundle_EndpointServer *server = spiffebundle_EndpointServer_New();
    err_t error = NO_ERROR;
    spiffeid_TrustDomain td = { .name = "example.org" };

    spiffebundle_Bundle *bundle
        = spiffebundle_Load(td, "./resources/example.org.bundle.jwks", &error);
    ck_assert_int_eq(error, NO_ERROR);
    spiffebundle_Source *source = spiffebundle_SourceFromBundle(bundle);
    ck_assert_ptr_ne(source, NULL);

    spiffebundle_EndpointServer_RegisterBundle(server, "/", source, td);
    int idx = shgeti(server->bundle_sources, "/");
    ck_assert_int_ge(idx, 0);
    ck_assert_ptr_eq(server->bundle_sources[idx].value, source);
    ck_assert_str_eq(server->bundle_tds[idx].value, td.name);

    spiffebundle_EndpointServer_UpdateBundle(server, "/",
                                             (spiffebundle_Source *) 0x2, td);
    ck_assert_ptr_eq(server->bundle_sources[idx].value,
                     (spiffebundle_Source *) 0x2);
    ck_assert_str_eq(server->bundle_tds[idx].value, td.name);
    server->bundle_sources[idx].value = source;

    // null tests
    spiffeid_TrustDomain null_td = { .name = NULL };
    ck_assert_int_eq(error, NO_ERROR);
    error = spiffebundle_EndpointServer_RegisterBundle(NULL, (void *) 0x1,
                                                       (void *) 0x1, td);
    ck_assert_int_ne(error, NO_ERROR);
    error = spiffebundle_EndpointServer_RegisterBundle((void *) 0x1, NULL,
                                                       (void *) 0x1, td);
    ck_assert_int_ne(error, NO_ERROR);
    error = spiffebundle_EndpointServer_RegisterBundle((void *) 0x1,
                                                       (void *) 0x1, NULL, td);
    ck_assert_int_ne(error, NO_ERROR);
    error = spiffebundle_EndpointServer_RegisterBundle(
        (void *) 0x1, (void *) 0x1, (void *) 0x1, null_td);
    ck_assert_int_ne(error, NO_ERROR);

    error = spiffebundle_EndpointServer_UpdateBundle(NULL, (void *) 0x1,
                                                     (void *) 0x1, td);
    ck_assert_int_ne(error, NO_ERROR);
    error = spiffebundle_EndpointServer_UpdateBundle((void *) 0x1, NULL,
                                                     (void *) 0x1, td);
    ck_assert_int_ne(error, NO_ERROR);
    error = spiffebundle_EndpointServer_UpdateBundle((void *) 0x1,
                                                     (void *) 0x1, NULL, td);
    ck_assert_int_ne(error, NO_ERROR);
    error = spiffebundle_EndpointServer_UpdateBundle(
        (void *) 0x1, (void *) 0x1, (void *) 0x1, null_td);
    ck_assert_int_ne(error, NO_ERROR);

    error = spiffebundle_EndpointServer_RemoveBundle(NULL, (void *) 0x1);
    ck_assert_int_ne(error, NO_ERROR);
    error = spiffebundle_EndpointServer_RemoveBundle((void *) 0x1, NULL);
    ck_assert_int_ne(error, NO_ERROR);

    error = spiffebundle_EndpointServer_RemoveBundle(server, "/");
    idx = shgeti(server->bundle_sources, "/");
    ck_assert_int_lt(idx, 0); // not found

    error = spiffebundle_EndpointServer_UpdateBundle(server, "/", (void *) 0x1,
                                                     td);
    ck_assert_int_ne(error, NO_ERROR);

    error = spiffebundle_EndpointServer_RemoveBundle(server, "/");
    ck_assert_int_ne(error, NO_ERROR);

    error = spiffebundle_EndpointServer_Free(server);
}
END_TEST

START_TEST(test_spiffebundle_EndpointServer_EndpointFunctions)
{
    spiffebundle_EndpointServer *server = spiffebundle_EndpointServer_New();
    err_t error = NO_ERROR;
    spiffeid_TrustDomain td = { .name = "example.org" };

    FILE *certs_file = fopen("./resources/example.org.crt", "r");
    ck_assert_ptr_ne(certs_file, NULL);
    FILE *key_file = fopen("./resources/example.org.key", "r");
    ck_assert_ptr_ne(key_file, NULL);
    X509 **certs
        = pemutil_ParseCertificates(FILE_to_bytes(certs_file), &error);
    ck_assert_ptr_ne(certs, NULL);
    ck_assert_int_eq(error, NO_ERROR);
    EVP_PKEY *priv_key
        = pemutil_ParsePrivateKey(FILE_to_bytes(key_file), &error);
    ck_assert_ptr_ne(priv_key, NULL);
    ck_assert_int_eq(error, NO_ERROR);

    fclose(certs_file);
    fclose(key_file);

    // add HTTPS_WEB endpoint functions
    spiffebundle_EndpointInfo *e_info1
        = spiffebundle_EndpointServer_AddHttpsWebEndpoint(
            server, "example.org", certs, priv_key, &error);
    ck_assert_ptr_ne(e_info1, NULL);
    ck_assert_int_eq(error, NO_ERROR);

    e_info1 = spiffebundle_EndpointServer_AddHttpsWebEndpoint(
        server, "example.org", certs, priv_key, &error);
    ck_assert_ptr_eq(e_info1, NULL);
    ck_assert_int_ne(error, NO_ERROR);

    // set HTTPS_WEB endpoint auth functions
    error = spiffebundle_EndpointServer_SetHttpsWebEndpointAuth(
        server, "example.org", certs, priv_key);
    ck_assert_int_eq(error, NO_ERROR);

    error = spiffebundle_EndpointServer_SetHttpsWebEndpointAuth(
        server, "example2.org", certs, priv_key);
    ck_assert_int_ne(error, NO_ERROR);

    // add HTTPS_SPIFFE endpoint functions
    x509svid_SVID *svid = x509svid_newSVID(certs, priv_key, &error);
    ck_assert_int_eq(error, NO_ERROR);
    x509svid_Source *source = x509svid_SourceFromSVID(svid);

    spiffebundle_EndpointInfo *e_info2
        = spiffebundle_EndpointServer_AddHttpsSpiffeEndpoint(
            server, "example.org", source, &error);
    ck_assert_ptr_eq(e_info2, NULL);
    ck_assert_int_eq(error, ERROR4);

    e_info2 = spiffebundle_EndpointServer_AddHttpsSpiffeEndpoint(
        server, "example2.org", source, &error);
    ck_assert_ptr_ne(e_info2, NULL);
    ck_assert_int_eq(error, NO_ERROR);

    // set HTTPS_SPIFFE endpoint source functions
    error = spiffebundle_EndpointServer_SetHttpsSpiffeEndpointSource(
        server, "example2.org", source);
    ck_assert_int_eq(error, NO_ERROR);

    error = spiffebundle_EndpointServer_SetHttpsSpiffeEndpointSource(
        server, "example3.org", source);
    ck_assert_int_ne(error, NO_ERROR);

    // get endpoint info
    e_info1 = spiffebundle_EndpointServer_GetEndpointInfo(
        server, "example.org", &error);
    ck_assert_ptr_ne(e_info1, NULL);
    ck_assert_int_eq(error, NO_ERROR);

    e_info1 = spiffebundle_EndpointServer_GetEndpointInfo(
        server, "example3.org", &error);
    ck_assert_ptr_eq(e_info1, NULL);
    ck_assert_int_ne(error, NO_ERROR);

    // remove endpoint
    error = spiffebundle_EndpointServer_RemoveEndpoint(server, "example.org");
    ck_assert_int_eq(error, NO_ERROR);

    error = spiffebundle_EndpointServer_RemoveEndpoint(server, "example.org");
    ck_assert_int_ne(error, NO_ERROR);

    error = spiffebundle_EndpointServer_RemoveEndpoint(server, "example2.org");
    ck_assert_int_eq(error, NO_ERROR);

    error = spiffebundle_EndpointServer_RemoveEndpoint(server, "example3.org");
    ck_assert_int_ne(error, NO_ERROR);

    error = spiffebundle_EndpointServer_Free(server);
    ck_assert_int_eq(error, NO_ERROR);

    // null/invalid argument tests
    e_info1 = spiffebundle_EndpointServer_AddHttpsWebEndpoint(NULL, NULL, NULL,
                                                              NULL, &error);
    ck_assert_ptr_eq(e_info1, NULL);
    ck_assert_int_ne(error, NO_ERROR);
    e_info1 = spiffebundle_EndpointServer_AddHttpsWebEndpoint(
        (void *) 0x1, NULL, NULL, NULL, &error);
    ck_assert_ptr_eq(e_info1, NULL);
    ck_assert_int_ne(error, NO_ERROR);

    e_info1 = spiffebundle_EndpointServer_AddHttpsWebEndpoint(
        (void *) 0x1, (void *) 0x1, NULL, NULL, &error);
    ck_assert_ptr_eq(e_info1, NULL);
    ck_assert_int_ne(error, NO_ERROR);

    e_info1 = spiffebundle_EndpointServer_AddHttpsWebEndpoint(
        (void *) 0x1, (void *) 0x1, certs, NULL, &error);
    ck_assert_ptr_eq(e_info1, NULL);
    ck_assert_int_ne(error, NO_ERROR);

    error = spiffebundle_EndpointServer_SetHttpsWebEndpointAuth(NULL, NULL,
                                                                NULL, NULL);
    ck_assert_int_ne(error, NO_ERROR);
    error = spiffebundle_EndpointServer_SetHttpsWebEndpointAuth(
        (void *) 0x1, NULL, NULL, NULL);
    ck_assert_int_ne(error, NO_ERROR);

    error = spiffebundle_EndpointServer_SetHttpsWebEndpointAuth(
        (void *) 0x1, (void *) 0x1, NULL, NULL);
    ck_assert_int_ne(error, NO_ERROR);

    error = spiffebundle_EndpointServer_SetHttpsWebEndpointAuth(
        (void *) 0x1, (void *) 0x1, certs, NULL);
    ck_assert_int_ne(error, NO_ERROR);

    e_info1 = spiffebundle_EndpointServer_AddHttpsSpiffeEndpoint(NULL, NULL,
                                                                 NULL, &error);
    ck_assert_ptr_eq(e_info1, NULL);
    ck_assert_int_ne(error, NO_ERROR);
    e_info1 = spiffebundle_EndpointServer_AddHttpsSpiffeEndpoint(
        (void *) 0x1, NULL, NULL, &error);
    ck_assert_ptr_eq(e_info1, NULL);
    ck_assert_int_ne(error, NO_ERROR);

    e_info1 = spiffebundle_EndpointServer_AddHttpsSpiffeEndpoint(
        (void *) 0x1, (void *) 0x1, NULL, &error);
    ck_assert_ptr_eq(e_info1, NULL);
    ck_assert_int_ne(error, NO_ERROR);

    error = spiffebundle_EndpointServer_SetHttpsSpiffeEndpointSource(
        NULL, NULL, NULL);
    ck_assert_int_ne(error, NO_ERROR);
    error = spiffebundle_EndpointServer_SetHttpsSpiffeEndpointSource(
        (void *) 0x1, NULL, NULL);
    ck_assert_int_ne(error, NO_ERROR);
    error = spiffebundle_EndpointServer_SetHttpsSpiffeEndpointSource(
        (void *) 0x1, (void *) 0x1, NULL);
    ck_assert_int_ne(error, NO_ERROR);

    e_info1 = spiffebundle_EndpointServer_GetEndpointInfo(NULL, "example.org",
                                                          &error);
    ck_assert_ptr_eq(e_info1, NULL);
    ck_assert_int_ne(error, NO_ERROR);

    e_info1 = spiffebundle_EndpointServer_GetEndpointInfo((void *) 0x1, NULL,
                                                          &error);
    ck_assert_ptr_eq(e_info1, NULL);
    ck_assert_int_ne(error, NO_ERROR);

    error = spiffebundle_EndpointServer_RemoveEndpoint(NULL, NULL);
    ck_assert_int_ne(error, NO_ERROR);
    error = spiffebundle_EndpointServer_RemoveEndpoint((void *) 0x1, NULL);
    ck_assert_int_ne(error, NO_ERROR);

    EVP_PKEY_free(priv_key);
    for(size_t i = 0, size = arrlen(certs); i < size; ++i) {
        X509_free(certs[i]);
    }
    arrfree(certs);
}
END_TEST

START_TEST(test_spiffebundle_EndpointServer_ServeFunctions)
{
    spiffebundle_EndpointServer *server = spiffebundle_EndpointServer_New();
    err_t error = NO_ERROR;
    spiffeid_TrustDomain td = { .name = "example.org" };

    FILE *certs_file = fopen("./resources/example.org.crt", "r");
    ck_assert_ptr_ne(certs_file, NULL);
    FILE *key_file = fopen("./resources/example.org.key", "r");
    ck_assert_ptr_ne(key_file, NULL);
    X509 **certs
        = pemutil_ParseCertificates(FILE_to_bytes(certs_file), &error);
    ck_assert_ptr_ne(certs, NULL);
    ck_assert_int_eq(error, NO_ERROR);
    EVP_PKEY *priv_key
        = pemutil_ParsePrivateKey(FILE_to_bytes(key_file), &error);
    ck_assert_ptr_ne(priv_key, NULL);
    ck_assert_int_eq(error, NO_ERROR);

    fclose(certs_file);
    fclose(key_file);

    spiffebundle_EndpointInfo *e_info1
        = spiffebundle_EndpointServer_AddHttpsWebEndpoint(
            server, "example.org", certs, priv_key, &error);
    ck_assert_ptr_ne(e_info1, NULL);
    ck_assert_int_eq(error, NO_ERROR);

    error = spiffebundle_EndpointServer_ServeEndpoint(server, "example.org",
                                                      445);
    ck_assert_int_eq(error, NO_ERROR);
    // struct timespec sleep_time = { .tv_sec = 1, .tv_nsec = 0 };
    // printf("sleeeep\n");
    // nanosleep(&sleep_time, NULL);
    ck_assert_ptr_ne(e_info1->threads[0].value, NULL);
    ck_assert(e_info1->threads[0].value->active);
    ck_assert_ptr_eq(e_info1->threads[0].value->endpoint_info, e_info1);
    ck_assert_int_eq(e_info1->threads[0].value->port, 445);

    error = spiffebundle_EndpointServer_StopEndpointThread(server,
                                                           "example.org", 446);
    ck_assert_int_ne(error, NO_ERROR);

    error = spiffebundle_EndpointServer_StopEndpointThread(server,
                                                           "example.org", 445);
    ck_assert_int_eq(error, NO_ERROR);

    // sleep_time.tv_sec = 1;
    // sleep_time.tv_nsec = 0;
    // printf("sleeeep\n");
    // nanosleep(&sleep_time, NULL);
    // error = spiffebundle_EndpointServer_ServeEndpoint(server, "example.org",
    //                                                   445);
    // ck_assert_int_eq(error, NO_ERROR);
    // sleep_time.tv_sec = 1;
    // sleep_time.tv_nsec = 0;
    // printf("sleeeep\n");
    // nanosleep(&sleep_time, NULL);
    // ck_assert_ptr_ne(e_info1->threads[0].value, NULL);
    // ck_assert(e_info1->threads[0].value->active);
    // ck_assert_ptr_eq(e_info1->threads[0].value->endpoint_info, e_info1);
    // ck_assert_int_eq(e_info1->threads[0].value->port, 445);

    // error = spiffebundle_EndpointServer_StopEndpoint(server, "example.org");
    // ck_assert_int_eq(error, NO_ERROR);
    // error = spiffebundle_EndpointServer_ServeEndpoint(server, "example.org",
    //                                                   445);
    // ck_assert_int_eq(error, NO_ERROR);

    // error = spiffebundle_EndpointServer_Stop(server);
    // ck_assert_int_eq(error, NO_ERROR);
}
END_TEST

// // Serve bundles using the set up protocol. Spawns a thread.
// err_t spiffebundle_EndpointServer_ServeEndpoint(
//     spiffebundle_EndpointServer *server, const char *base_url, uint port);

// // Stop serving from indicated thread.
// err_t spiffebundle_EndpointServer_StopEndpoint(
//     spiffebundle_EndpointServer *server, const char *base_url);

// // Stops serving from all threads.
// err_t spiffebundle_EndpointServer_StopAll(spiffebundle_EndpointServer
// *server);

Suite *endpoint_server_suite(void)
{
    Suite *s = suite_create("spiffebundle_server");
    TCase *tc_core = tcase_create("core");
    tcase_add_test(tc_core, test_spiffebundle_EndpointInfo_New_Free);
    tcase_add_test(tc_core, test_spiffebundle_EndpointServer_New_Free);
    tcase_add_test(tc_core, test_spiffebundle_EndpointServer_BundleFunctions);
    tcase_add_test(tc_core,
                   test_spiffebundle_EndpointServer_EndpointFunctions);
    tcase_add_test(tc_core, test_spiffebundle_EndpointServer_ServeFunctions);
    // tcase_add_test(tc_core, test_federation_Endpoint_fetch_WEB);
    // tcase_add_test(tc_core, test_federation_Endpoint_fetch_SPIFFE);

    // tcase_set_timeout(tc_core,20);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(int argc, char **argv)
{
    Suite *s = endpoint_server_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
