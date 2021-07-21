#include "c-spiffe/bundle/spiffebundle.h"
#include "c-spiffe/federation/federation.h"
#include "c-spiffe/internal/pemutil.h"
#include "c-spiffe/spiffeid/spiffeid.h"
#include "c-spiffe/spiffetls/spiffetls.h"
#include "c-spiffe/utils/error.h"
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
    ck_assert_int_eq(error, ERR_EXISTS);

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

    error = spiffebundle_EndpointServer_ServeEndpoint(server, "example.org",
                                                      445);
    ck_assert_int_eq(error, NO_ERROR);
    ck_assert_ptr_ne(e_info1->threads[0].value, NULL);
    ck_assert(e_info1->threads[0].value->active);
    ck_assert_ptr_eq(e_info1->threads[0].value->endpoint_info, e_info1);
    ck_assert_int_eq(e_info1->threads[0].value->port, 445);

    error = spiffebundle_EndpointServer_StopEndpoint(server, "example.org");
    ck_assert_int_eq(error, NO_ERROR);
    error = spiffebundle_EndpointServer_ServeEndpoint(server, "example.org",
                                                      445);
    ck_assert_int_eq(error, NO_ERROR);

    error = spiffebundle_EndpointServer_Stop(server);
    ck_assert_int_eq(error, NO_ERROR);
}
END_TEST

err_t write_HTTPS(SSL *conn, const char *response, const char **headers,
                  size_t num_headers, const char *content);

size_t read_HTTPS(SSL *conn, const char *buf, size_t buf_size,
                  const char **method, size_t *method_len, const char **path,
                  size_t *path_len, int *minor_version,
                  struct phr_header *headers, size_t *num_headers,
                  size_t *prevbuflen, err_t *err);
err_t serve_HTTPS(SSL *conn, spiffebundle_EndpointServer *server);

char *http_test_response = "GET / HTTP/1.1";
char *http_test_headers[] = { "Host: example.org", "User-Agent: Mozilla/5.0",
                              "Accept-Encoding: gzip, deflate, br" };
int http_test_num_headers = 3;
char *http_test_content = "{}";

int serve_function(void *arg);

int mockHTTPS(void *arg)
{
    int socket = (int) arg;

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);
    int use_cert = SSL_CTX_use_certificate_file(
        ctx, "./resources/example.org.crt", SSL_FILETYPE_PEM);
    ck_assert_int_eq(use_cert, 1);
    SSL *cSSL = SSL_new(ctx);
    ck_assert_ptr_ne(cSSL, NULL);
    SSL_set_fd(cSSL, socket);
    int ssl_error = SSL_connect(cSSL);

    ck_assert_int_eq(ssl_error, 1);
    int error = SSL_get_error(cSSL, ssl_error);

    ck_assert_int_eq(error, NO_ERROR);

    int ret = write_HTTPS(cSSL, http_test_response, http_test_headers,
                          http_test_num_headers, http_test_content);

    ck_assert_int_eq(ret, NO_ERROR);
}

START_TEST(test_spiffebundle_EndpointServer_HTTPSFunctions)
{
    // read_HTTPS tests
    int sockets[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);
    err_t err;
    // write https to socket 1
    // read from socket 2
    SSL_CTX *sslctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_options(sslctx, SSL_OP_SINGLE_DH_USE);
    int use_cert = SSL_CTX_use_certificate_file(
        sslctx, "./resources/example.org.crt", SSL_FILETYPE_PEM);
    ck_assert_int_ne(use_cert, NULL);
    int use_prv = SSL_CTX_use_PrivateKey_file(
        sslctx, "./resources/example.org.key", SSL_FILETYPE_PEM);
    ck_assert_int_ne(use_prv, NULL);
    SSL *cSSL = SSL_new(sslctx);
    SSL_set_fd(cSSL, sockets[0]);

    thrd_t thread;
    thrd_create(&thread, mockHTTPS, sockets[1]);

    // Here is the SSL Accept portion.  Now all reads and writes must use SSL
    int ssl_err = SSL_accept(cSSL);
    ck_assert_int_eq(ssl_err, 1);

    char buf[4096], *method, *path;
    int minor_version;
    struct phr_header headers[100];
    size_t buflen = 0, prevbuflen = 0, method_len = 0, path_len = 0,
           num_headers = sizeof(headers) / sizeof(headers[0]);
    ssize_t rret;

    buflen = read_HTTPS(cSSL, buf, sizeof(buf), &method, &method_len, &path,
                        &path_len, &minor_version, headers, &num_headers,
                        &prevbuflen, &err);
    buf[buflen] = '\0';
    ck_assert_int_eq(err, NO_ERROR);
    printf("buf:%s\n", buf);
    ck_assert_int_eq(strlen(buf), strlen(http_test_response) + 2
                                      + strlen(http_test_headers[0]) + 2
                                      + strlen(http_test_headers[1]) + 2
                                      + strlen(http_test_headers[2]) + 2
                                      + strlen(http_test_content) + 6);
    /// buf will be modified after this
    method[method_len] = '\0';
    path[path_len] = '\0';

    for(int i = 0; i < num_headers; i++) {
        char *name = headers[i].name;
        char *value = headers[i].value;

        name[headers[i].name_len] = '\0';
        value[headers[i].value_len] = '\0';
    }

    ck_assert_str_eq(method, "GET");
    ck_assert_str_eq(path, "/");
    ck_assert_int_eq(num_headers, 3);
    ck_assert_int_eq(minor_version, 1);
    ck_assert_str_eq(headers[0].value, "example.org");
    ck_assert_str_eq(headers[0].name, "Host");
    ck_assert_str_eq(headers[0].value, "example.org");
    ck_assert_str_eq(headers[1].name, "User-Agent");
    ck_assert_str_eq(headers[1].value, "Mozilla/5.0");
    ck_assert_str_eq(headers[2].name, "Accept-Encoding");
    ck_assert_str_eq(headers[2].value, "gzip, deflate, br");
}
END_TEST

START_TEST(test_spiffebundle_EndpointServer_Serve_HTTPSFunctions)
{

    spiffebundle_EndpointServer *server = spiffebundle_EndpointServer_New();
    err_t error = NO_ERROR;
    spiffeid_TrustDomain td = { .name = "example.org" };

    spiffebundle_Bundle *bundle
        = spiffebundle_Load(td, "./resources/example.org.bundle.jwks", &error);
    spiffebundle_Source *source = spiffebundle_SourceFromBundle(bundle);
    spiffebundle_EndpointServer_RegisterBundle(server, "/", source, td);

    int sockets[2];
    int res = socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);
    ck_assert_int_eq(res, 0);

    SSL_CTX *sslctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_options(sslctx, SSL_OP_SINGLE_DH_USE);
    int use_cert = SSL_CTX_use_certificate_file(
        sslctx, "./resources/example.org.crt", SSL_FILETYPE_PEM);
    ck_assert_int_ne(use_cert, NULL);
    int use_prv = SSL_CTX_use_PrivateKey_file(
        sslctx, "./resources/example.org.key", SSL_FILETYPE_PEM);
    ck_assert_int_ne(use_prv, NULL);

    SSL *cSSL = SSL_new(sslctx);
    SSL_set_fd(cSSL, sockets[0]);

    thrd_t thread;
    thrd_create(&thread, mockHTTPS, sockets[1]);
    int ssl_err = SSL_accept(cSSL);
    ck_assert_int_eq(ssl_err, 1);

    error = serve_HTTPS(cSSL, server);
    ck_assert_int_eq(error, NO_ERROR);
}
END_TEST

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
    tcase_add_test(tc_core, test_spiffebundle_EndpointServer_HTTPSFunctions);
    tcase_add_test(tc_core,
                   test_spiffebundle_EndpointServer_Serve_HTTPSFunctions);

    // tcase_set_timeout(tc_core,20);
    suite_add_tcase(s, tc_core);

    return s;
}

void init_openssl()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

int main(int argc, char **argv)
{
    init_openssl();
    Suite *s = endpoint_server_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
