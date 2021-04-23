/*
 * Filename: c-spiffe/requestor/requestor.cpp
 * Path: c-spiffe/requestor
 * Created Date: Monday, December 21nd 2020, 10:32:38 am
 * Author: Rodrigo Lopes (rlc2@cesar.org.br)
 *
 * Copyright (c) 2020 CESAR
 */

#include "svid/x509svid/src/svid.h"
#include "workload.grpc.pb.h"
#include "workload.pb.h"
#include "workload/src/client.h"
#include "workload_mock.grpc.pb.h"
#include <check.h>
#include <gmock/gmock.h>
#include <grpc/grpc.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/test/mock_stream.h>
#include <iostream> //keep at top
#include <openssl/bio.h>
#include <openssl/pem.h>

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SetArgPointee;
using ::testing::WithArg;
using ::testing::WithArgs;

/// DONE: implemented in client.cc, not part of public interface:

x509bundle_Set *workloadapi_parseX509Bundles(const X509SVIDResponse *rep,
                                             err_t *err);
x509bundle_Bundle *workloadapi_parseX509Bundle(string_t id,
                                               const byte *bundle_bytes,
                                               const size_t len, err_t *err);

workloadapi_X509Context *workloadapi_parseX509Context(X509SVIDResponse *resp,
                                                      err_t *err);

x509svid_SVID **workloadapi_parseX509SVIDs(X509SVIDResponse *resp,
                                           bool firstOnly, err_t *err);
jwtsvid_SVID *workloadapi_parseJWTSVID(const JWTSVIDResponse *resp,
                                       jwtsvid_Params *params, err_t *err);
jwtbundle_Set *workloadapi_parseJWTBundles(const JWTBundlesResponse *resp,
                                           err_t *err);

START_TEST(test_workloadapi_parseX509Bundles)
{
    const int ITERS = 4;

    FILE *f = fopen("./resources/certs.pem", "r");
    ck_assert(f != NULL);
    string_t buffer = FILE_to_string(f);
    fclose(f);

    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, buffer);
    arrfree(buffer);

    unsigned char der_bytes[10000];
    unsigned char *pout = der_bytes;

    for(int i = 0; i < ITERS; ++i) {
        X509 *cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
        if(cert) {
            i2d_X509(cert, &pout);
        }
    }

    X509SVIDResponse rep;

    auto new_svid = rep.mutable_svids()->Add();
    new_svid->set_spiffe_id("spiffe://example1.com");
    new_svid->set_bundle(der_bytes, pout - der_bytes);

    new_svid = rep.mutable_svids()->Add();
    new_svid->set_spiffe_id("spiffe://example2.com");
    new_svid->set_bundle(der_bytes, pout - der_bytes);

    auto new_bundle = rep.mutable_federated_bundles();
    (*new_bundle)["spiffe://example3.com"]
        = std::string((char *) der_bytes, pout - der_bytes);

    err_t err = NO_ERROR;
    x509bundle_Set *set = workloadapi_parseX509Bundles(&rep, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(set, NULL);
    ck_assert_uint_eq(x509bundle_Set_Len(set), 3);

    x509bundle_Set_Free(set);

    // NULL response test
    set = workloadapi_parseX509Bundles(NULL, &err);

    ck_assert_ptr_eq(set, NULL);
    ck_assert_int_eq(err, ERROR1);
}
END_TEST

START_TEST(test_workloadapi_NewClient)
{
    // when we create a new client
    err_t error = NO_ERROR;
    workloadapi_Client *client = workloadapi_NewClient(&error);

    // then all parameters are empty
    ck_assert_ptr_ne(client, NULL);
    ck_assert_ptr_eq(client->stub, NULL);
    ck_assert_ptr_eq(client->address, NULL);
    ck_assert_int_eq(error, NO_ERROR);
    ck_assert(client->closed);
    ck_assert_int_eq(arrlen(client->headers), 0);

    error = workloadapi_Client_Free(client);
    ck_assert_int_eq(error, NO_ERROR);

    // NULL client test.
    error = workloadapi_Client_Free(NULL);
    ck_assert_int_eq(error, ERROR1);
}
END_TEST

// workloadapi_parseX509Context
START_TEST(test_workloadapi_parseX509Context)
{
    const int ITERS = 4;

    FILE *fed_certs_file = fopen("./resources/certs.pem", "r");
    ck_assert(fed_certs_file != NULL);
    unsigned char bundle_der_bytes[10000];
    unsigned char *bundle_pout = bundle_der_bytes;
    unsigned char der_bytes[10000];
    unsigned char *pout = der_bytes;
    for(int i = 0; i < ITERS; ++i) {
        X509 *cert = PEM_read_X509(fed_certs_file, NULL, NULL, NULL);
        ck_assert(cert != NULL);
        if(cert) {
            i2d_X509(cert, &bundle_pout);
        }
    }
    fclose(fed_certs_file);

    X509SVIDResponse rep;

    // set federated bundles
    auto new_bundle = rep.mutable_federated_bundles();
    (*new_bundle)["spiffe://example3.com"] = std::string(
        (char *) bundle_der_bytes, bundle_pout - bundle_der_bytes);

    // set certificates and private key
    FILE *certs_file
        = fopen("./resources/good-leaf-and-intermediate.pem", "r");
    FILE *pkey_file = fopen("./resources/key-pkcs8-ecdsa.pem", "r");
    ck_assert(certs_file != NULL && pkey_file != NULL);
    X509 *cert1 = PEM_read_X509(certs_file, NULL, NULL, NULL);
    X509 *cert2 = PEM_read_X509(certs_file, NULL, NULL, NULL);
    EVP_PKEY *pkey = PEM_read_PrivateKey(pkey_file, NULL, NULL, NULL);
    ck_assert(cert1 != NULL && cert2 != NULL && pkey != NULL);
    fclose(certs_file);
    fclose(pkey_file);

    //=====FIRST SVID=====
    auto new_svid = rep.mutable_svids()->Add();
    new_svid->set_spiffe_id("spiffe://example1.com/example_1");
    new_svid->set_bundle(bundle_der_bytes, bundle_pout - bundle_der_bytes);

    pout = der_bytes;
    i2d_X509(cert1, &pout);
    i2d_X509(cert2, &pout);
    new_svid->set_x509_svid(der_bytes, pout - der_bytes);

    pout = der_bytes;
    i2d_PrivateKey(pkey, &pout);
    new_svid->set_x509_svid_key(der_bytes, pout - der_bytes);
    //=====SECOND SVID=====
    new_svid = rep.mutable_svids()->Add();
    new_svid->set_spiffe_id("spiffe://example2.com/example_2");
    new_svid->set_bundle(bundle_der_bytes, bundle_pout - bundle_der_bytes);

    pout = der_bytes;
    i2d_X509(cert1, &pout);
    i2d_X509(cert2, &pout);
    new_svid->set_x509_svid(der_bytes, pout - der_bytes);

    pout = der_bytes;
    i2d_PrivateKey(pkey, &pout);
    new_svid->set_x509_svid_key(der_bytes, pout - der_bytes);

    err_t err;

    workloadapi_X509Context *ctx = workloadapi_parseX509Context(&rep, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    // check context has been returned
    ck_assert_ptr_ne(ctx, NULL);
    // check all bundles have been created
    ck_assert_uint_eq(x509bundle_Set_Len(ctx->bundles), 3);
    // ditto for svids
    ck_assert_uint_eq(arrlenu(ctx->svids), 2);

    string_arr_t paths = NULL;
    arrput(paths, string_new("/workload-1"));
    arrput(paths, string_new("/workload-1"));

    string_arr_t tds = NULL;
    arrput(tds, string_new("example.org"));
    arrput(tds, string_new("example.org"));

    // test if SVIDs have been parsed properly
    for(int i = 0; i < arrlen(ctx->svids); i++) {
        ck_assert_str_eq(paths[i], ctx->svids[i]->id.path);
        ck_assert_str_eq(tds[i], ctx->svids[i]->id.td.name);
    }

    // needed freeing
    X509_free(cert1);
    X509_free(cert2);
    EVP_PKEY_free(pkey);
    util_string_arr_t_Free(tds);
    util_string_arr_t_Free(paths);
    x509bundle_Set_Free(ctx->bundles);
    for(int i = 0; i < arrlen(ctx->svids); i++) {
        x509svid_SVID_Free(ctx->svids[i]);
    }
    arrfree(ctx->svids);
    free(ctx);

    // NULL response test
    ctx = workloadapi_parseX509Context(NULL, &err);

    ck_assert_ptr_eq(ctx, NULL);
    ck_assert_int_eq(err, ERROR2);
}
END_TEST

ACTION(set_single_SVID_response)
{
    const int ITERS = 4;

    FILE *fed_certs_file = fopen("./resources/certs.pem", "r");
    ck_assert(fed_certs_file != NULL);
    unsigned char bundle_der_bytes[10000];
    unsigned char *bundle_pout = bundle_der_bytes;
    unsigned char der_bytes[10000];
    unsigned char *pout = der_bytes;
    for(int i = 0; i < ITERS; ++i) {
        X509 *cert = PEM_read_X509(fed_certs_file, NULL, NULL, NULL);
        ck_assert(cert != NULL);
        if(cert) {
            i2d_X509(cert, &bundle_pout);
        }
    }
    fclose(fed_certs_file);

    // set federated bundles
    auto new_bundle = arg0->mutable_federated_bundles();
    (*new_bundle)["spiffe://federated.com"] = std::string(
        (char *) bundle_der_bytes, bundle_pout - bundle_der_bytes);

    FILE *certs_file
        = fopen("./resources/good-leaf-and-intermediate.pem", "r");
    FILE *pkey_file = fopen("./resources/key-pkcs8-ecdsa.pem", "r");
    X509 *cert1 = PEM_read_X509(certs_file, NULL, NULL, NULL);
    X509 *cert2 = PEM_read_X509(certs_file, NULL, NULL, NULL);
    fclose(certs_file);
    EVP_PKEY *pkey = PEM_read_PrivateKey(pkey_file, NULL, NULL, NULL);
    ck_assert(cert1 != NULL && cert2 != NULL && pkey != NULL);

    // fclose(pkey_file);

    //=====FIRST SVID=====
    auto new_svid = arg0->mutable_svids()->Add();
    new_svid->set_spiffe_id("spiffe://example.org/workload-1");
    new_svid->set_bundle(bundle_der_bytes, bundle_pout - bundle_der_bytes);

    pout = der_bytes;
    i2d_X509(cert1, &pout);
    i2d_X509(cert2, &pout);
    new_svid->set_x509_svid(der_bytes, pout - der_bytes);

    pout = der_bytes;
    i2d_PrivateKey(pkey, &pout);
    new_svid->set_x509_svid_key(der_bytes, pout - der_bytes);
}

ACTION(set_JWTBundle_response)
{
    JWTBundlesResponse *resp = arg0;

    FILE *f = fopen("./resources/jwk_keys.json", "r");
    ck_assert_ptr_ne(f, NULL);

    string_t str = FILE_to_string(f);
    fclose(f);

    auto *bundles = resp->mutable_bundles();
    (*bundles)["key0"] = string_new(str);
    (*bundles)["key1"] = string_new(str);

    arrfree(str);
}

START_TEST(test_workloadapi_Client_Close)
{
    // normal constructor test

    err_t err = NO_ERROR;
    workloadapi_Client *client = workloadapi_NewClient(&err);

    MockSpiffeWorkloadAPIStub *stub = new MockSpiffeWorkloadAPIStub();
    workloadapi_Client_SetStub(client, stub);
    workloadapi_Client_setDefaultAddressOption(client, NULL);
    workloadapi_Client_setDefaultHeaderOption(client, NULL);

    err = workloadapi_Client_Connect(client);

    ck_assert(!client->owns_stub);
    ck_assert_ptr_eq(client->stub, stub);
    ck_assert(!client->closed);

    // NULL client test.
    err = workloadapi_Client_Close(NULL);
    ck_assert_int_eq(err, ERROR1);

    // close client test.
    err = workloadapi_Client_Close(client);
    ck_assert(!client->owns_stub);
    ck_assert_ptr_eq(client->stub, NULL);
    ck_assert(client->closed);
    ck_assert_int_eq(err, NO_ERROR);

    // close client with null stub test.
    err = workloadapi_Client_Close(client);
    ck_assert_int_eq(err, ERROR3);

    // close closed client test.
    client->stub = (workloadapi_Stub *) 0x1; // check-passing invalid value
    err = workloadapi_Client_Close(client);
    ck_assert_int_eq(err, ERROR2);

    client->stub = NULL; // mem safety

    // free client
    err = workloadapi_Client_Free(client);
    ck_assert_int_eq(err, NO_ERROR);
}
END_TEST

START_TEST(test_workloadapi_Client_Connect_uses_stub)
{
    err_t err = NO_ERROR;

    // NULL client test.
    err = workloadapi_Client_Connect(NULL);
    ck_assert_int_eq(err, ERROR1);

    // normal constructor test
    workloadapi_Client *client = workloadapi_NewClient(&err);
    ck_assert_ptr_ne(client, NULL);
    ck_assert_int_eq(err, NO_ERROR);

    MockSpiffeWorkloadAPIStub *stub = new MockSpiffeWorkloadAPIStub();
    err = workloadapi_Client_SetStub(client, stub);

    // set the owned flag so when we add a new stub the previous is deleted on
    // SetStub
    client->owns_stub = true;
    stub = new MockSpiffeWorkloadAPIStub();

    err = workloadapi_Client_SetStub(client, (workloadapi_Stub *) 1);
    ck_assert_int_eq(err, NO_ERROR);
    ck_assert_ptr_eq(client->stub, (workloadapi_Stub *) 1);

    err = workloadapi_Client_SetStub(client, stub);
    ck_assert_int_eq(err, NO_ERROR);
    ck_assert_ptr_eq(client->stub, stub);

    // null test to setStub
    err = workloadapi_Client_SetStub(NULL, NULL);
    ck_assert_int_eq(err, ERROR1);

    // setAddress tests
    err = workloadapi_Client_SetAddress(NULL, NULL);
    ck_assert_int_eq(err, ERROR1);

    err = workloadapi_Client_SetAddress(client, NULL);
    ck_assert_int_eq(err, ERROR2);

    // sets address to "fake"
    err = workloadapi_Client_SetAddress(client, "unix:///tmp/not_agent.sock");
    ck_assert_str_eq(client->address, "unix:///tmp/not_agent.sock");
    ck_assert_int_eq(err, NO_ERROR);

    string_t old_address = client->address;

    // new address, so the old string is freed
    workloadapi_Client_setDefaultAddressOption(client, NULL);
    ck_assert_str_eq(client->address, "unix:///tmp/agent.sock");
    ck_assert_int_eq(err, NO_ERROR);
    ck_assert_ptr_ne(client->address, old_address);

    // setHeader tests
    err = workloadapi_Client_AddHeader(NULL, NULL, NULL);
    ck_assert_int_eq(err, ERROR1);

    workloadapi_Client_setDefaultHeaderOption(client, NULL);

    err = workloadapi_Client_Connect(client);

    ck_assert_ptr_eq(client->stub, stub);

    auto cr = new grpc::testing::MockClientReader<X509SVIDResponse>();
    EXPECT_CALL(*stub, FetchX509SVIDRaw(_, _)).WillOnce(Return(cr));

    EXPECT_CALL(*cr, Read(_))
        .WillOnce(DoAll(WithArg<0>(set_single_SVID_response()), Return(true)));
    //   .WillOnce(Return(false));

    x509svid_SVID *svid = workloadapi_Client_FetchX509SVID(client, &err);
    workloadapi_Client_Close(client);
    workloadapi_Client_Free(client);
    ck_assert_ptr_ne(svid, NULL);
    ck_assert_str_eq(svid->id.td.name, "example.org");
    delete stub;
}
END_TEST

START_TEST(test_workloadapi_parseJWTSVID_null_or_empty)
{
    // given null response and params
    // when we try to parse the response for JWTSVIDS
    err_t err = NO_ERROR;
    jwtsvid_SVID *svid = workloadapi_parseJWTSVID(NULL, NULL, &err);

    // then we should get no SVID, with an ERROR1 error
    ck_assert_ptr_eq(svid, NULL);
    ck_assert_int_eq(err, ERROR1); // NULL pointer error

    // given misc parameters and an empty response (no svid)
    string_t aud = string_new("audience1");
    jwtsvid_Params params = { aud, NULL, NULL };
    JWTSVIDResponse *resp = new JWTSVIDResponse();
    resp->clear_svids();

    // when we try to parse the response for a JWTSVID
    svid = workloadapi_parseJWTSVID(resp, &params, &err);

    // then we should get no SVID, with a ERROR2 error
    ck_assert_ptr_eq(svid, NULL);
    ck_assert_int_eq(err, ERROR2);
    util_string_t_Free(aud);
}
END_TEST

START_TEST(test_workloadapi_parseJWTBundles_null_or_empty)
{
    // given null response and params
    // when we try to parse the response for bundles
    err_t err = NO_ERROR;
    jwtbundle_Set *set = workloadapi_parseJWTBundles(NULL, &err);

    // then we should get no SVID, with an ERROR1 error
    ck_assert_ptr_eq(set, NULL);
    ck_assert_int_eq(err, ERROR1); // NULL pointer error
}
END_TEST

START_TEST(test_workloadapi_Client_FetchX509Context)
{
    // normal constructor test
    const char *addr = "unix:///tmp/agent.sock";
    err_t err = NO_ERROR;
    workloadapi_Client *client = workloadapi_NewClient(&err);
    auto cr = new grpc::testing::MockClientReader<X509SVIDResponse>();

    MockSpiffeWorkloadAPIStub *stub = new MockSpiffeWorkloadAPIStub();
    workloadapi_Client_SetStub(client, stub);
    workloadapi_Client_setDefaultAddressOption(client, NULL);
    workloadapi_Client_setDefaultHeaderOption(client, NULL);

    err = workloadapi_Client_Connect(client);

    ck_assert_ptr_eq(client->stub, stub);

    EXPECT_CALL(*stub, FetchX509SVIDRaw(_, _)).WillOnce(Return(cr));

    EXPECT_CALL(*cr, Read(_))
        .WillOnce(DoAll(WithArg<0>(set_single_SVID_response()), Return(true)));
    //   .WillOnce(Return(false));

    workloadapi_X509Context *ctx
        = workloadapi_Client_FetchX509Context(client, &err);
    workloadapi_Client_Close(client);
    workloadapi_Client_Free(client);
    ck_assert_ptr_ne(ctx->svids, NULL);

    ck_assert_ptr_ne(ctx->bundles, NULL);
    ck_assert_str_eq(ctx->svids[0]->id.td.name, "example.org");
    delete stub;
    free(ctx);
}
END_TEST

START_TEST(test_workloadapi_Client_FetchX509Bundles)
{
    // normal constructor test
    const char *addr = "unix:///tmp/agent.sock";
    err_t err = NO_ERROR;
    workloadapi_Client *client = workloadapi_NewClient(&err);
    auto cr = new grpc::testing::MockClientReader<X509SVIDResponse>();

    MockSpiffeWorkloadAPIStub *stub = new MockSpiffeWorkloadAPIStub();
    workloadapi_Client_SetStub(client, stub);
    workloadapi_Client_setDefaultAddressOption(client, NULL);
    workloadapi_Client_setDefaultHeaderOption(client, NULL);

    err = workloadapi_Client_Connect(client);

    ck_assert_ptr_eq(client->stub, stub);

    EXPECT_CALL(*stub, FetchX509SVIDRaw(_, _)).WillOnce(Return(cr));

    EXPECT_CALL(*cr, Read(_))
        .WillOnce(DoAll(WithArg<0>(set_single_SVID_response()), Return(true)));

    x509bundle_Set *set = workloadapi_Client_FetchX509Bundles(client, &err);
    workloadapi_Client_Close(client);
    workloadapi_Client_Free(client);
    ck_assert_ptr_ne(set, NULL);
    ck_assert_int_eq(x509bundle_Set_Len(set), 2); // trust domain + federated
    ck_assert_ptr_ne(set->bundles, NULL);
    ck_assert_str_eq(set->bundles[0].value[0].td.name, "example.org");
    ck_assert_str_eq(set->bundles[1].value[0].td.name, "federated.com");
    delete stub;
    x509bundle_Set_Free(set);
}
END_TEST

START_TEST(test_workloadapi_Client_FetchJWTBundles)
{
    // normal constructor test
    const char *addr = "unix:///tmp/agent.sock";
    err_t err = NO_ERROR;
    workloadapi_Client *client = workloadapi_NewClient(&err);
    auto cr = new grpc::testing::MockClientReader<JWTBundlesResponse>();

    MockSpiffeWorkloadAPIStub *stub = new MockSpiffeWorkloadAPIStub();
    workloadapi_Client_SetStub(client, stub);
    workloadapi_Client_setDefaultAddressOption(client, NULL);
    workloadapi_Client_setDefaultHeaderOption(client, NULL);

    err = workloadapi_Client_Connect(client);

    ck_assert_ptr_eq(client->stub, stub);

    EXPECT_CALL(*stub, FetchJWTBundlesRaw(_, _)).WillOnce(Return(cr));
    EXPECT_CALL(*cr, Read(_))
        .WillOnce(DoAll(WithArg<0>(set_JWTBundle_response()), Return(true)));

    jwtbundle_Set *set = workloadapi_Client_FetchJWTBundles(client, &err);
    workloadapi_Client_Close(client);
    workloadapi_Client_Free(client);

    ck_assert_ptr_ne(set, NULL);
    ck_assert_uint_eq(jwtbundle_Set_Len(set), 2);

    delete stub;
    jwtbundle_Set_Free(set);
}
END_TEST

const char token1[]
    = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImZmM2M1Yzk2LTM5MmUtNDZ"
      "lZi1hODM5LTZmZjE2MDI3YWY3OCJ9."
      "eyJzdWIiOiJzcGlmZmU6Ly9leGFtcGxlLmNvbS93b3JrbG9hZDEiLCJuYW1lIjoiSm9"
      "obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTYyMDAwMDAwMH0."
      "sbbqzgX6d3gH2O2tBAHdmehfHBv3QH29WOIDrPmuyOl6FfFxJaBmo6D3jX3Fm7_"
      "Wh0gM7GagbC5hkPBKZlUYR-DYg5lvp9QbHP9r1BLIqB-zfhHGYgfq_"
      "cbCh0ud1ytv9AjQw9k1oUyJUZfkB8kC1IfTZPVQQIgnKFeauT3lmPxIpEjueyn-"
      "98Qbbnv705wKlrU0KMGK7ac1Sj78yclqdmcfnT7oEE8zDdSs27Uh4lEIsO58zW6fEe_"
      "NE_M6BnaubI35eOoegwSkfCWT54fWa8jwn1OjLF_"
      "K0e5FxF4i8YJHlpY54rge6grAPAJiKKRei__-ZC8osYOEpmhGltu2BQ";

ACTION(set_JWTSVID_response)
{
    JWTSVIDRequest req = arg0;
    JWTSVIDResponse *resp = arg1;
    auto svid = resp->add_svids();
    svid->set_spiffe_id(req.spiffe_id());
    svid->set_svid(token1);
}

START_TEST(test_workloadapi_Client_FetchJWTSVID)
{
    // normal constructor test
    const char *addr = "unix:///tmp/agent.sock";
    err_t err = NO_ERROR;
    workloadapi_Client *client = workloadapi_NewClient(&err);

    MockSpiffeWorkloadAPIStub *stub = new MockSpiffeWorkloadAPIStub();
    workloadapi_Client_SetStub(client, stub);
    workloadapi_Client_setDefaultAddressOption(client, NULL);
    workloadapi_Client_setDefaultHeaderOption(client, NULL);

    err = workloadapi_Client_Connect(client);

    ck_assert_ptr_eq(client->stub, stub);

    EXPECT_CALL(*stub, FetchJWTSVID(_, _, _))
        .WillOnce(DoAll(WithArgs<1, 2>(set_JWTSVID_response()),
                        Return(grpc::Status::OK)));

    jwtsvid_Params params = { .audience = NULL, // {string_new("audience1")},
                              .extra_audiences = NULL,
                              .subject = spiffeid_FromString(
                                  "spiffe://example.org/workload-1", &err) };

    jwtsvid_SVID *svid
        = workloadapi_Client_FetchJWTSVID(client, &params, &err);

    workloadapi_Client_Close(client);
    workloadapi_Client_Free(client);

    ck_assert_ptr_ne(svid, NULL);
    ck_assert_ptr_eq(svid->audience, NULL);
    ck_assert_ptr_ne(svid->claims, NULL);
    ck_assert_uint_eq(shlenu(svid->claims), 4);
    ck_assert_int_ge(shgeti(svid->claims, "sub"), 0);
    ck_assert_int_ge(shgeti(svid->claims, "name"), 0);
    ck_assert_int_ge(shgeti(svid->claims, "iat"), 0);
    ck_assert_int_ge(shgeti(svid->claims, "exp"), 0);
    ck_assert_int_eq(svid->expiry, 1620000000);
    ck_assert_ptr_ne(svid->id.path, NULL);
    ck_assert_str_eq(svid->id.path, "/workload1");
    ck_assert_ptr_ne(svid->id.td.name, NULL);
    ck_assert_str_eq(svid->id.td.name, "example.com");
    ck_assert_ptr_ne(svid->token, NULL);
    ck_assert_str_eq(svid->token, token1);

    delete stub;
    arrfree(params.audience);
    util_string_arr_t_Free(params.extra_audiences);
    spiffeid_ID_Free(&(params.subject));
    jwtsvid_SVID_Free(svid);
}
END_TEST

const char token2[]
    = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImZmM2M1Yzk2LTM5MmUtNDZlZi1"
      "hODM5LTZmZjE2MDI3YWY3OCJ9."
      "eyJzdWIiOiJzcGlmZmU6Ly9leGFtcGxlLmNvbS93b3JrbG9hZDEiLCJhdWQiOiJzcGlmZmU"
      "6Ly9leGFtcGxlLm9yZy9hdWRpZW5jZTEiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MT"
      "YyMzkwMjIsImV4cCI6MTYyMDAwMDAwMH0.fU-XY-AwR_BjKkvR3yafygceTB1AUP3xsp_"
      "6KLn2MZBlA-LPalbayXZxYasR_t7Fc6cRHtYpNof4341BxgFPuzXIM_"
      "3kPw5Bno9ij4M5hKr7vvpuDfB2Bhl6UzPWI_"
      "BJQWB18wc7L2L7kUVdWCavEU8Jv6JwVPsyQufruMHCbBOpJRaL-"
      "4YEPOWLUOLlJxMgHNfnAdXy15GTODDO3Y5DlC_BjTcMdYB6aS_"
      "8QiFplVjwJ0YvKalj7wB2hdlSYdB8C9exWqQn9xUZhTK_IJ_Yc1DQG9LhKMEjVls0Lwnv3-"
      "eb7o58PTneMGYjTwsD4Ladf3L94izRK0FCfINfwvL2TA";

START_TEST(test_workloadapi_Client_ValidateJWTSVID)
{
    // normal constructor test
    const char *addr = "unix:///tmp/agent.sock";
    err_t err = NO_ERROR;
    workloadapi_Client *client = workloadapi_NewClient(&err);

    MockSpiffeWorkloadAPIStub *stub = new MockSpiffeWorkloadAPIStub();
    workloadapi_Client_SetStub(client, stub);
    workloadapi_Client_setDefaultAddressOption(client, NULL);
    workloadapi_Client_setDefaultHeaderOption(client, NULL);

    err = workloadapi_Client_Connect(client);

    ck_assert_ptr_eq(client->stub, stub);

    EXPECT_CALL(*stub, ValidateJWTSVID(_, _, _))
        .WillOnce(Return(grpc::Status::OK));

    string_t my_token = string_new(token2);
    char audience[] = "spiffe://example.org/audience1";
    jwtsvid_SVID *svid
        = workloadapi_Client_ValidateJWTSVID(client, my_token, audience, &err);
    arrfree(my_token);

    workloadapi_Client_Close(client);
    workloadapi_Client_Free(client);

    ck_assert_ptr_ne(svid, NULL);
    ck_assert_ptr_ne(svid->claims, NULL);
    ck_assert_ptr_ne(svid->audience, NULL);
    ck_assert_uint_eq(arrlenu(svid->audience), 1);
    ck_assert_uint_eq(shlenu(svid->claims), 5);
    ck_assert_int_ge(shgeti(svid->claims, "sub"), 0);
    ck_assert_int_ge(shgeti(svid->claims, "aud"), 0);
    ck_assert_int_ge(shgeti(svid->claims, "name"), 0);
    ck_assert_int_ge(shgeti(svid->claims, "iat"), 0);
    ck_assert_int_ge(shgeti(svid->claims, "exp"), 0);
    ck_assert_int_eq(svid->expiry, 1620000000);
    ck_assert_ptr_ne(svid->id.path, NULL);
    ck_assert_str_eq(svid->id.path, "/workload1");
    ck_assert_ptr_ne(svid->id.td.name, NULL);
    ck_assert_str_eq(svid->id.td.name, "example.com");
    ck_assert_ptr_ne(svid->token, NULL);
    ck_assert_str_eq(svid->token, token2);

    delete stub;
    jwtsvid_SVID_Free(svid);
}
END_TEST

ACTION(set_double_SVID_response)
{
    const int ITERS = 4;

    FILE *fed_certs_file = fopen("./resources/certs.pem", "r");
    ck_assert(fed_certs_file != NULL);
    unsigned char bundle_der_bytes[10000];
    unsigned char *bundle_pout = bundle_der_bytes;
    unsigned char der_bytes[10000];
    unsigned char *pout = der_bytes;
    for(int i = 0; i < ITERS; ++i) {
        X509 *cert = PEM_read_X509(fed_certs_file, NULL, NULL, NULL);
        ck_assert(cert != NULL);
        if(cert) {
            i2d_X509(cert, &bundle_pout);
        }
    }
    fclose(fed_certs_file);

    // set federated bundles
    auto new_bundle = arg0->mutable_federated_bundles();
    (*new_bundle)["spiffe://example3.com"] = std::string(
        (char *) bundle_der_bytes, bundle_pout - bundle_der_bytes);

    FILE *certs_file
        = fopen("./resources/good-leaf-and-intermediate.pem", "r");
    FILE *pkey_file = fopen("./resources/key-pkcs8-ecdsa.pem", "r");
    ck_assert(certs_file != NULL && pkey_file != NULL);
    X509 *cert1 = PEM_read_X509(certs_file, NULL, NULL, NULL);
    X509 *cert2 = PEM_read_X509(certs_file, NULL, NULL, NULL);
    EVP_PKEY *pkey = PEM_read_PrivateKey(pkey_file, NULL, NULL, NULL);
    ck_assert(cert1 != NULL && cert2 != NULL && pkey != NULL);
    fclose(certs_file);
    fclose(pkey_file);

    //=====FIRST SVID=====
    auto new_svid = arg0->mutable_svids()->Add();
    new_svid->set_spiffe_id("spiffe://example1.com/example_1");
    new_svid->set_bundle(bundle_der_bytes, bundle_pout - bundle_der_bytes);

    pout = der_bytes;
    i2d_X509(cert1, &pout);
    i2d_X509(cert2, &pout);
    new_svid->set_x509_svid(der_bytes, pout - der_bytes);

    pout = der_bytes;
    i2d_PrivateKey(pkey, &pout);
    new_svid->set_x509_svid_key(der_bytes, pout - der_bytes);
    //=====SECOND SVID=====
    new_svid = arg0->mutable_svids()->Add();
    new_svid->set_spiffe_id("spiffe://example2.com/example_2");
    new_svid->set_bundle(bundle_der_bytes, bundle_pout - bundle_der_bytes);

    pout = der_bytes;
    i2d_X509(cert1, &pout);
    i2d_X509(cert2, &pout);
    new_svid->set_x509_svid(der_bytes, pout - der_bytes);

    pout = der_bytes;
    i2d_PrivateKey(pkey, &pout);
    new_svid->set_x509_svid_key(der_bytes, pout - der_bytes);

    err_t err;

    // needed freeing
    X509_free(cert1);
    X509_free(cert2);
    EVP_PKEY_free(pkey);
}

void callback_Watch_context_test(workloadapi_X509Context *ctx, void *ctxs)
{
    workloadapi_X509Context ***arr = (workloadapi_X509Context ***) ctxs;
    auto svids = ctx->svids;
    auto bundles = ctx->bundles;
    ctx = (workloadapi_X509Context *) calloc(1, sizeof *ctx);
    ctx->svids = svids;
    ctx->bundles = bundles;
    arrpush((*arr), ctx);
}

START_TEST(test_workloadapi_Client_WatchX509Context)
{
    err_t err = NO_ERROR;
    workloadapi_Client *client = workloadapi_NewClient(&err);
    auto cr = new grpc::testing::MockClientReader<X509SVIDResponse>();

    MockSpiffeWorkloadAPIStub *stub = new MockSpiffeWorkloadAPIStub();
    workloadapi_Client_SetStub(client, stub);
    workloadapi_Client_setDefaultAddressOption(client, NULL);
    workloadapi_Client_setDefaultHeaderOption(client, NULL);

    ck_assert_ptr_eq(client->stub, stub);

    EXPECT_CALL(*stub, FetchX509SVIDRaw(_, _)).WillRepeatedly(Return(cr));

    EXPECT_CALL(*cr, Read(_))
        .WillOnce(DoAll(WithArg<0>(set_single_SVID_response()), Return(true)))
        .WillOnce(DoAll(WithArg<0>(set_double_SVID_response()), Return(true)))
        .WillOnce(DoAll(WithArg<0>(set_single_SVID_response()), Return(true)))
        .WillOnce(DoAll(WithArg<0>(set_double_SVID_response()), Return(true)))
        .WillRepeatedly(Return(false));

    grpc::Status status
        = grpc::Status(grpc::StatusCode::CANCELLED, "abort???");

    EXPECT_CALL(*cr, Finish()).WillOnce(Return(status));

    err = workloadapi_Client_Connect(client);
    workloadapi_WatcherConfig config;
    config.client = client;
    config.client_options = NULL;

    workloadapi_X509Context **ctxs = NULL;
    // arrsetcap(ctxs, 5);
    workloadapi_X509Callback callback;
    callback.args = &ctxs;
    callback.func = callback_Watch_context_test;

    workloadapi_Watcher *watcher
        = workloadapi_newWatcher(config, callback, &err);

    err = workloadapi_Client_WatchX509Context(client, watcher);

    ck_assert_int_eq(err, grpc::StatusCode::CANCELLED);

    workloadapi_Client_Close(client);
    workloadapi_Client_Free(client);

    ck_assert_int_eq(arrlen(ctxs), 4);
    ck_assert_ptr_ne(ctxs[0], NULL);
    ck_assert_ptr_ne(ctxs[0]->svids, NULL);
    ck_assert_int_eq(arrlen(ctxs[0]->svids), 1);

    x509bundle_Set_Free(ctxs[0]->bundles);
    x509svid_SVID_Free(ctxs[0]->svids[0]);
    arrpop(ctxs[0]->svids);
    free(ctxs[0]);

    ck_assert_ptr_ne(ctxs[1], NULL);
    ck_assert_ptr_ne(ctxs[1]->svids, NULL);
    ck_assert_int_eq(arrlen(ctxs[1]->svids), 2);

    x509bundle_Set_Free(ctxs[1]->bundles);
    x509svid_SVID_Free(ctxs[1]->svids[0]);
    x509svid_SVID_Free(ctxs[1]->svids[1]);
    arrpop(ctxs[1]->svids);
    free(ctxs[1]);

    ck_assert_ptr_ne(ctxs[2], NULL);
    ck_assert_ptr_ne(ctxs[2]->svids, NULL);
    ck_assert_int_eq(arrlen(ctxs[2]->svids), 1);

    x509bundle_Set_Free(ctxs[2]->bundles);
    x509svid_SVID_Free(ctxs[2]->svids[0]);
    arrpop(ctxs[2]->svids);
    arrpop(ctxs[2]->svids);
    free(ctxs[2]);

    ck_assert_ptr_ne(ctxs[3], NULL);
    ck_assert_ptr_ne(ctxs[3]->svids, NULL);
    ck_assert_int_eq(arrlen(ctxs[3]->svids), 2);

    x509bundle_Set_Free(ctxs[3]->bundles);
    x509svid_SVID_Free(ctxs[3]->svids[0]);
    x509svid_SVID_Free(ctxs[3]->svids[1]);
    arrpop(ctxs[3]->svids);
    free(ctxs[3]);

    arrpop(ctxs);
    arrpop(ctxs);
    arrpop(ctxs);
    arrpop(ctxs);

    delete stub;

    // NULL tests

    err = workloadapi_Client_watchX509Context(client, watcher,
                                              (workloadapi_Backoff *) NULL);
    ck_assert_int_eq(err, ERROR2);

    watcher = NULL;
    err = workloadapi_Client_WatchX509Context(client, watcher);
    ck_assert_int_eq(err, ERROR2);

    err = workloadapi_Client_watchX509Context(client, watcher,
                                              (workloadapi_Backoff *) 0x1);
    ck_assert_int_eq(err, ERROR2);

    client = NULL;
    err = workloadapi_Client_WatchX509Context(client, watcher);
    ck_assert_int_eq(err, ERROR1);
    err = workloadapi_Client_watchX509Context(client, watcher,
                                              (workloadapi_Backoff *) 0x1);
    ck_assert_int_eq(err, ERROR2);
}
END_TEST

void callback_Watch_Jwtbundle_test(jwtbundle_Set *set, void *sets)
{
    jwtbundle_Set ***sets_ = (jwtbundle_Set ***) sets;
    jwtbundle_Set *newer = jwtbundle_Set_Clone((jwtbundle_Set *) set);
    arrpush((*sets_), newer);
}

START_TEST(test_workloadapi_Client_WatchJWTBundles)
{
    err_t err = NO_ERROR;
    workloadapi_Client *client = workloadapi_NewClient(&err);
    auto cr = new grpc::testing::MockClientReader<JWTBundlesResponse>();

    MockSpiffeWorkloadAPIStub *stub = new MockSpiffeWorkloadAPIStub();
    workloadapi_Client_SetStub(client, stub);

    ck_assert_ptr_eq(client->stub, stub);

    EXPECT_CALL(*stub, FetchJWTBundlesRaw(_, _)).WillRepeatedly(Return(cr));

    EXPECT_CALL(*cr, Read(_))
        .WillOnce(DoAll(WithArg<0>(set_JWTBundle_response()), Return(true)))
        .WillOnce(DoAll(WithArg<0>(set_JWTBundle_response()), Return(true)))
        .WillRepeatedly(Return(false));

    grpc::Status status
        = grpc::Status(grpc::StatusCode::CANCELLED, "abort???");

    EXPECT_CALL(*cr, Finish()).WillOnce(Return(status));

    err = workloadapi_Client_Connect(client);
    workloadapi_JWTWatcherConfig config;
    config.client = client;
    config.client_options = NULL;

    jwtbundle_Set **sets = NULL;

    workloadapi_JWTCallback callback;
    callback.args = &sets;
    callback.func = callback_Watch_Jwtbundle_test;

    workloadapi_JWTWatcher *watcher
        = workloadapi_newJWTWatcher(config, callback, &err);

    err = workloadapi_Client_WatchJWTBundles(client, watcher);

    ck_assert_int_eq(err, grpc::StatusCode::CANCELLED);

    workloadapi_Client_Close(client);
    workloadapi_Client_Free(client);

    ck_assert_ptr_ne(sets, NULL);
    ck_assert_int_eq(arrlen(sets), 2);

    ck_assert_ptr_ne(sets[0], NULL);
    ck_assert_ptr_ne(sets[0]->bundles, NULL);
    ck_assert_int_eq(jwtbundle_Set_Len(sets[0]), 2);
    jwtbundle_Set_Free(sets[0]);

    ck_assert_ptr_ne(sets[1], NULL);
    ck_assert_ptr_ne(sets[1]->bundles, NULL);
    ck_assert_int_eq(jwtbundle_Set_Len(sets[1]), 2);
    jwtbundle_Set_Free(sets[1]);

    arrpop(sets);
    arrpop(sets);

    delete stub;

    // NULL tests

    err = workloadapi_Client_watchJWTBundles(client, watcher,
                                             (workloadapi_Backoff *) NULL);
    ck_assert_int_eq(err, ERROR2);

    watcher = NULL;
    err = workloadapi_Client_WatchJWTBundles(client, watcher);
    ck_assert_int_eq(err, ERROR2);

    err = workloadapi_Client_watchJWTBundles(client, watcher,
                                             (workloadapi_Backoff *) 0x1);
    ck_assert_int_eq(err, ERROR2);

    client = NULL;
    err = workloadapi_Client_WatchJWTBundles(client, watcher);
    ck_assert_int_eq(err, ERROR1);
    err = workloadapi_Client_watchJWTBundles(client, watcher,
                                             (workloadapi_Backoff *) 0x1);
    ck_assert_int_eq(err, ERROR2);
}
END_TEST

START_TEST(test_workloadapi_Client_FetchX509SVIDs)
{
    // normal constructor test
    const char *addr = "unix:///tmp/agent.sock";
    err_t err = NO_ERROR;
    workloadapi_Client *client = workloadapi_NewClient(&err);
    auto cr = new grpc::testing::MockClientReader<X509SVIDResponse>();

    MockSpiffeWorkloadAPIStub *stub = new MockSpiffeWorkloadAPIStub();
    workloadapi_Client_SetStub(client, stub);
    workloadapi_Client_setDefaultAddressOption(client, NULL);
    workloadapi_Client_setDefaultHeaderOption(client, NULL);

    err = workloadapi_Client_Connect(client);

    ck_assert_ptr_eq(client->stub, stub);

    EXPECT_CALL(*stub, FetchX509SVIDRaw(_, _)).WillOnce(Return(cr));

    EXPECT_CALL(*cr, Read(_))
        .WillOnce(DoAll(WithArg<0>(set_double_SVID_response()), Return(true)));
    //   .WillOnce(Return(false));

    x509svid_SVID **svids = workloadapi_Client_FetchX509SVIDs(client, &err);
    workloadapi_Client_Close(client);
    workloadapi_Client_Free(client);

    ck_assert_ptr_ne(svids, NULL);
    ck_assert_ptr_ne(svids[0], NULL);
    ck_assert_ptr_ne(svids[1], NULL);
    ck_assert_ptr_ne(svids[0], svids[1]);
    ck_assert_str_eq(svids[0]->id.path, "/workload-1");
    ck_assert_str_eq(svids[1]->id.path, "/workload-1");

    ck_assert_str_eq(svids[0]->id.td.name, "example.org");
    ck_assert_str_eq(svids[1]->id.td.name, "example.org");

    delete stub;
    arrfree(svids);
}
END_TEST

Suite *client_suite(void)
{
    Suite *s = suite_create("client");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_workloadapi_parseX509Bundles);
    tcase_add_test(tc_core, test_workloadapi_parseX509Context);
    tcase_add_test(tc_core, test_workloadapi_NewClient);
    tcase_add_test(tc_core, test_workloadapi_Client_Connect_uses_stub);
    tcase_add_test(tc_core, test_workloadapi_Client_Close);
    tcase_add_test(tc_core, test_workloadapi_Client_FetchX509Context);
    tcase_add_test(tc_core, test_workloadapi_Client_FetchJWTBundles);
    tcase_add_test(tc_core, test_workloadapi_Client_FetchX509Bundles);
    tcase_add_test(tc_core, test_workloadapi_Client_WatchX509Context);
    tcase_add_test(tc_core, test_workloadapi_Client_WatchJWTBundles);
    tcase_add_test(tc_core, test_workloadapi_Client_FetchX509SVIDs);
    tcase_add_test(tc_core, test_workloadapi_Client_FetchJWTSVID);
    tcase_add_test(tc_core, test_workloadapi_Client_ValidateJWTSVID);
    tcase_add_test(tc_core, test_workloadapi_parseJWTSVID_null_or_empty);
    tcase_add_test(tc_core, test_workloadapi_parseJWTBundles_null_or_empty);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(int argc, char **argv)
{
    Suite *s = client_suite();
    SRunner *sr = srunner_create(s);
    testing::InitGoogleMock(&argc, argv);
    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
