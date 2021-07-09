#include "bundle/spiffebundle.h"
#include "federation/federation.h"
#include "spiffeid/spiffeid.h"
#include "spiffetls/spiffetls.h"
#include "utils/util.h"
#include <check.h>

START_TEST(test_spiffebundle_EndpointServer_Info_New_Free)
{
    spiffebundle_EndpointServer_EndpointInfo *info
        = spiffebundle_EndpointServer_EndpointInfo_New();

    ck_assert_ptr_ne(info, NULL);
    ck_assert_int_eq(info->active, false);
    ck_assert_ptr_eq(info->listen_mode, NULL);
    ck_assert_ptr_eq(info->server, NULL);
    ck_assert_int_eq(info->port, 0);
    ck_assert_int_eq(info->thread, 0);
    ck_assert_ptr_eq(info->url, NULL);

    err_t error = spiffebundle_EndpointServer_EndpointInfo_Free(info);
    ck_assert_int_eq(error, NO_ERROR);
    error = spiffebundle_EndpointServer_EndpointInfo_Free(NULL);
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

START_TEST(test_spiffebundle_EndpointServer_RegisterBundle)
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

    spiffebundle_EndpointServer_UpdateBundle(server, "/", (spiffebundle_Source*)0x2, td);
    ck_assert_ptr_eq(server->bundle_sources[idx].value, (spiffebundle_Source*)0x2);
    ck_assert_str_eq(server->bundle_tds[idx].value, td.name);
    server->bundle_sources[idx].value = source;

    spiffebundle_EndpointServer_RemoveBundle(server, "/");
    idx = shgeti(server->bundle_sources, "/");
    ck_assert_int_lt(idx, 0); // not found

    error = spiffebundle_EndpointServer_Free(server);
    ck_assert_int_ne(error, NO_ERROR);
}
END_TEST

START_TEST(test_spiffebundle_EndpointServer_AddEndpoints)
{
    spiffebundle_EndpointServer *server = spiffebundle_EndpointServer_New();
    err_t error = NO_ERROR;
    spiffeid_TrustDomain td = { .name = "example.org" };

    FILE *certs_file = fopen("./resources/example.org.crt", "r");
    FILE *key_file = fopen("./resources/example.org.key", "r");

    X509 **certs
        = pemutil_ParseCertificates(FILE_to_bytes(certs_file), &error);
    EVP_PKEY *priv_key
        = pemutil_ParsePrivateKey(FILE_to_bytes(key_file), &error);
    
    spiffebundle_EndpointServer_AddHttpsWebEndpoint(server, "example.org",
                                                    certs, priv_key, &error);
    error = spiffebundle_EndpointServer_Free(server);
    ck_assert_int_ne(error, NO_ERROR);
}
END_TEST

// // load keys to use with 'https_web'
// // register a HTTPS_WEB endpoint, for starting with
// // spiffebundle_EndpointServer_ServeEndpoint
// spiffebundle_EndpointServer_EndpointInfo *
// spiffebundle_EndpointServer_AddHttpsWebEndpoint(
//     spiffebundle_EndpointServer *server, const char *base_url, X509 **cert,
//     EVP_PKEY *priv_key, err_t *error);

// err_t spiffebundle_EndpointServer_SetHttpsWebEndpointAuth(
//     spiffebundle_EndpointServer *server, const char *base_url, X509 **cert,
//     EVP_PKEY *priv_key);

// // Register a HTTPS_SPIFFE endpoint, for starting with
// // spiffebundle_EndpointServer_ServeEndpoint.
// spiffebundle_EndpointServer_EndpointInfo *
// spiffebundle_EndpointServer_AddHttpsSpiffeEndpoint(
//     spiffebundle_EndpointServer *server, const char *base_url,
//     x509svid_Source *svid_source, err_t *error);

// err_t spiffebundle_EndpointServer_SetHttpsSpiffeEndpointSource(
//     spiffebundle_EndpointServer *server, const char *base_url,
//     x509svid_Source *svid_source);

// // Get info for serving thread.
// spiffebundle_EndpointServer_EndpointInfo *
// spiffebundle_EndpointServer_GetEndpointInfo(
//     spiffebundle_EndpointServer *server, const char *base_url, err_t
//     *error);

// // Remove endpoint from server.
// err_t spiffebundle_EndpointServer_RemoveEndpoint(
//     spiffebundle_EndpointServer *server, const char *base_url);

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
    tcase_add_test(tc_core, test_spiffebundle_EndpointServer_Info_New_Free);
    tcase_add_test(tc_core, test_spiffebundle_EndpointServer_New_Free);
    // tcase_add_test(tc_core, test_federation_Endpoint_Config_SPIFFE);
    // tcase_add_test(tc_core, test_federation_Endpoint_Config_WEB);
    // tcase_add_test(tc_core, test_federation_Endpoint_get_bundle);
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
