/*
 * Filename: c-spiffe/requestor/requestor.cpp
 * Path: c-spiffe/requestor
 * Created Date: Monday, December 21nd 2020, 10:32:38 am
 * Author: Rodrigo Lopes (rlc2@cesar.org.br)
 * 
 * Copyright (c) 2020 CESAR
 */

#include <iostream> //keep at top
#include <grpc/grpc.h>
#include <grpcpp/grpcpp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <check.h>
#include <gmock/gmock.h>
#include <grpcpp/test/mock_stream.h>
#include "workload.pb.h"
#include "workload.grpc.pb.h"
#include "workload_mock.grpc.pb.h"
#include "../../svid/x509svid/src/svid.h"
#include "../src/client.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SetArgPointee;
using ::testing::WithArg;

///DONE: implemented in client.cc, not part of public interface:
 
x509bundle_Set* workloadapi_parseX509Bundles(const X509SVIDResponse *rep, 
                                            err_t *err);
x509bundle_Bundle* workloadapi_parseX509Bundle(string_t id,
                                            const byte *bundle_bytes,
                                            const size_t len,
                                            err_t *err);

workloadapi_X509Context* workloadapi_parseX509Context(X509SVIDResponse *resp, err_t *err);

x509svid_SVID** workloadapi_parseX509SVIDs(X509SVIDResponse *resp,
                                            bool firstOnly,
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

    for(int i = 0; i < ITERS; ++i)
    {
        X509 *cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
        if(cert)
        {
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
    (*new_bundle)["spiffe://example3.com"] = 
        std::string((char*) der_bytes, pout - der_bytes);

    err_t err = NO_ERROR;
    x509bundle_Set *set = workloadapi_parseX509Bundles(&rep, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(set, NULL);
    ck_assert_uint_eq(x509bundle_Set_Len(set), 3);

    x509bundle_Set_Free(set);
}
END_TEST

START_TEST(test_workloadapi_NewClient)
{
    err_t error = NO_ERROR;
    workloadapi_Client* client = workloadapi_NewClient(&error);
    ck_assert_ptr_ne(client,NULL);
    ck_assert_ptr_eq(client->stub,NULL);
    ck_assert_ptr_eq(client->address,NULL);
    ck_assert_int_eq(error,NO_ERROR);
    ck_assert(client->closed);
    ck_assert_int_eq(arrlen(client->headers),0);

    error = workloadapi_Client_Free(client);
    ck_assert_int_eq(error,NO_ERROR);
}
END_TEST

//workloadapi_parseX509Context
START_TEST(test_workloadapi_parseX509Context)
{
    const int ITERS = 4;

    FILE *fed_certs_file = fopen("./resources/certs.pem", "r");
    ck_assert(fed_certs_file != NULL);
    unsigned char bundle_der_bytes[10000];
    unsigned char *bundle_pout = bundle_der_bytes;
    unsigned char der_bytes[10000];
    unsigned char *pout = der_bytes;
    for(int i = 0; i < ITERS; ++i)
    {
        X509 *cert = PEM_read_X509(fed_certs_file, NULL, NULL, NULL);
        ck_assert(cert != NULL);
        if(cert)
        {
            i2d_X509(cert, &bundle_pout);
        }
    }
    fclose(fed_certs_file);

    X509SVIDResponse rep;
    
    //set federated bundles
    auto new_bundle = rep.mutable_federated_bundles();
    (*new_bundle)["spiffe://example3.com"] = 
        std::string((char*) bundle_der_bytes, bundle_pout - bundle_der_bytes);
    ///TODO: add files to resources/
    //set certificates and private key
    FILE *certs_file = fopen("./resources/good-leaf-and-intermediate.pem", "r");
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
    //check context has been returned
    ck_assert_ptr_ne(ctx, NULL);
    //check all bundles have been created
    ck_assert_uint_eq(x509bundle_Set_Len(ctx->Bundles), 3);
    //ditto for svids
    ck_assert_uint_eq(arrlenu(ctx->svids), 2);
    
    string_arr_t paths = NULL;
    arrput(paths,"/workload-1");
    arrput(paths,"/workload-1");
    
    string_arr_t tds = NULL;
    arrput(tds,"example.org");
    arrput(tds,"example.org");

    //test if SVIDs have been parsed properly
    for (int i = 0; i < arrlen(ctx->svids);i++)
    {
        ck_assert_str_eq(paths[i],ctx->svids[i]->id.path);
        ck_assert_str_eq(tds[i],ctx->svids[i]->id.td.name);
    }

    //needed freeing
    X509_free(cert1);
    X509_free(cert2);
    EVP_PKEY_free(pkey);
    arrfree(tds);
    arrfree(paths);
    x509bundle_Set_Free(ctx->Bundles);
    for (int i = 0; i < arrlen(ctx->svids);i++)
    {
        x509svid_SVID_Free(ctx->svids[i],true);
    }
    arrfree(ctx->svids);
    free(ctx);
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
    for(int i = 0; i < ITERS; ++i)
    {
        X509 *cert = PEM_read_X509(fed_certs_file, NULL, NULL, NULL);
        ck_assert(cert != NULL);
        if(cert)
        {
            i2d_X509(cert, &bundle_pout);
        }
    }
    fclose(fed_certs_file);

    
    //set federated bundles
    auto new_bundle = arg0->mutable_federated_bundles();
    (*new_bundle)["spiffe://federated.com"] = 
        std::string((char*) bundle_der_bytes, bundle_pout - bundle_der_bytes);
    ///TODO: add files to resources/
    //set certificates and private key
    FILE *certs_file = fopen("./resources/good-leaf-and-intermediate.pem", "r");
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


START_TEST(test_workloadapi_Client_Close)
{
    //normal constructor test
    
    err_t err = NO_ERROR;
    workloadapi_Client* client = workloadapi_NewClient(&err);
    auto cr = new grpc::testing::MockClientReader<X509SVIDResponse>();

    MockSpiffeWorkloadAPIStub *stub = new MockSpiffeWorkloadAPIStub();
    workloadapi_Client_SetStub(client,stub);
    workloadapi_Client_setDefaultAddressOption(client,NULL);
    workloadapi_Client_setDefaultHeaderOption(client,NULL);

    err = workloadapi_Client_Connect(client); 

    ck_assert(!client->ownsStub);
    ck_assert_ptr_eq(client->stub,stub);
    ck_assert(!client->closed);

    err = workloadapi_Client_Close(client);

    ck_assert(!client->ownsStub);
    ck_assert_ptr_eq(client->stub,NULL);
    ck_assert(client->closed);
    ck_assert_int_eq(err,NO_ERROR);
    
}
END_TEST

START_TEST(test_workloadapi_Client_Connect_uses_stub)
{
    //normal constructor test
    err_t err = NO_ERROR;
    workloadapi_Client* client = workloadapi_NewClient(&err);
    auto cr = new grpc::testing::MockClientReader<X509SVIDResponse>();

    MockSpiffeWorkloadAPIStub* stub = new MockSpiffeWorkloadAPIStub();
    workloadapi_Client_SetStub(client,stub);
    workloadapi_Client_setDefaultAddressOption(client,NULL);
    workloadapi_Client_setDefaultHeaderOption(client,NULL);

    err = workloadapi_Client_Connect(client); 

    ck_assert_ptr_eq(client->stub,stub);
    
    EXPECT_CALL(*stub, FetchX509SVIDRaw(_,_))
        .WillOnce(Return(cr));

    EXPECT_CALL(*cr, Read(_))
        .WillOnce(DoAll(WithArg<0>(set_single_SVID_response()),Return(true)));
    //   .WillOnce(Return(false));
    
    
    x509svid_SVID* svid = workloadapi_Client_FetchX509SVID(client,&err);
    workloadapi_Client_Close(client);
    workloadapi_Client_Free(client);
    ck_assert_ptr_ne(svid,NULL);
    ck_assert_str_eq(svid->id.td.name,"example.org");
    delete stub;
}
END_TEST


START_TEST(test_workloadapi_Client_FetchX509Context)
{
    //normal constructor test
    const char* addr = "unix:///tmp/agent.sock";
    err_t err = NO_ERROR;
    workloadapi_Client* client = workloadapi_NewClient(&err);
    auto cr = new grpc::testing::MockClientReader<X509SVIDResponse>();

    MockSpiffeWorkloadAPIStub* stub = new MockSpiffeWorkloadAPIStub();
    workloadapi_Client_SetStub(client,stub);
    workloadapi_Client_setDefaultAddressOption(client,NULL);
    workloadapi_Client_setDefaultHeaderOption(client,NULL);

    err = workloadapi_Client_Connect(client); 

    ck_assert_ptr_eq(client->stub,stub);
    
    EXPECT_CALL(*stub, FetchX509SVIDRaw(_,_))
        .WillOnce(Return(cr));

    EXPECT_CALL(*cr, Read(_))
        .WillOnce(DoAll(WithArg<0>(set_single_SVID_response()),Return(true)));
    //   .WillOnce(Return(false));
    
    
    workloadapi_X509Context* ctx = workloadapi_Client_FetchX509Context(client,&err);
    workloadapi_Client_Close(client);
    workloadapi_Client_Free(client);
    ck_assert_ptr_ne(ctx->svids,NULL);

    ck_assert_ptr_ne(ctx->Bundles,NULL);
    ck_assert_str_eq(ctx->svids[0]->id.td.name,"example.org");
    delete stub;
    free(ctx);
}
END_TEST

ACTION(set_double_SVID_response){
    
    const int ITERS = 4;

    FILE *fed_certs_file = fopen("./resources/certs.pem", "r");
    ck_assert(fed_certs_file != NULL);
    unsigned char bundle_der_bytes[10000];
    unsigned char *bundle_pout = bundle_der_bytes;
    unsigned char der_bytes[10000];
    unsigned char *pout = der_bytes;
    for(int i = 0; i < ITERS; ++i)
    {
        X509 *cert = PEM_read_X509(fed_certs_file, NULL, NULL, NULL);
        ck_assert(cert != NULL);
        if(cert)
        {
            i2d_X509(cert, &bundle_pout);
        }
    }
    fclose(fed_certs_file);
    
    //set federated bundles
    auto new_bundle = arg0->mutable_federated_bundles();
    (*new_bundle)["spiffe://example3.com"] = 
        std::string((char*) bundle_der_bytes, bundle_pout - bundle_der_bytes);
    ///TODO: add files to resources/
    //set certificates and private key
    FILE *certs_file = fopen("./resources/good-leaf-and-intermediate.pem", "r");
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

    //needed freeing
    X509_free(cert1);
    X509_free(cert2);
    EVP_PKEY_free(pkey);
    
}

void callback_Watch_context_test(workloadapi_X509Context * ctx,void* ctxs){
    workloadapi_X509Context ***arr = (workloadapi_X509Context***) ctxs;
    auto svids = ctx->svids;
    auto bundles = ctx->Bundles;
    ctx = (workloadapi_X509Context*) calloc(1,sizeof *ctx);
    ctx->svids = svids;
    ctx->Bundles = bundles;
    arrpush((*arr),ctx);

    return;
}

START_TEST(test_workloadapi_Client_WatchX509Context)
{
    err_t err = NO_ERROR;
    workloadapi_Client* client = workloadapi_NewClient(&err);
    auto cr = new grpc::testing::MockClientReader<X509SVIDResponse>();

    MockSpiffeWorkloadAPIStub* stub = new MockSpiffeWorkloadAPIStub();
    workloadapi_Client_SetStub(client,stub);
    workloadapi_Client_setDefaultAddressOption(client,NULL);
    workloadapi_Client_setDefaultHeaderOption(client,NULL);

    ck_assert_ptr_eq(client->stub,stub);
    
    EXPECT_CALL(*stub, FetchX509SVIDRaw(_,_))
        .WillRepeatedly(Return(cr));

    EXPECT_CALL(*cr, Read(_))
        .WillOnce(DoAll(WithArg<0>(set_single_SVID_response()),Return(true)))
        .WillOnce(DoAll(WithArg<0>(set_double_SVID_response()),Return(true)))
        .WillOnce(DoAll(WithArg<0>(set_single_SVID_response()),Return(true)))
        .WillOnce(DoAll(WithArg<0>(set_double_SVID_response()),Return(true)))
        .WillRepeatedly(Return(false));
    
    grpc::Status status = grpc::Status(grpc::StatusCode::CANCELLED,"abort???");
    
    EXPECT_CALL(*cr, Finish())
        .WillOnce(Return(status));

    err = workloadapi_Client_Connect(client);
    workloadapi_WatcherConfig config;
    config.client = client;
    config.clientOptions = NULL;

    workloadapi_X509Context** ctxs = NULL;
    arrsetcap(ctxs,5);
    workloadapi_X509Callback callback;
    callback.args = &ctxs;
    callback.func = callback_Watch_context_test;

    workloadapi_Watcher* watcher = workloadapi_newWatcher(config,callback,&err);    
    
    err =  workloadapi_Client_WatchX509Context(client,watcher);

    ck_assert_int_eq(err,grpc::StatusCode::CANCELLED);

    workloadapi_Client_Close(client);
    workloadapi_Client_Free(client);

    ck_assert_int_eq(arrlen(ctxs),4);
    ck_assert_ptr_ne(ctxs[0],NULL);
    ck_assert_ptr_ne(ctxs[0]->svids,NULL);
    ck_assert_int_eq(arrlen(ctxs[0]->svids),1);

    ck_assert_ptr_ne(ctxs[1],NULL);
    ck_assert_ptr_ne(ctxs[1]->svids,NULL);
    ck_assert_int_eq(arrlen(ctxs[1]->svids),2);

    ck_assert_ptr_ne(ctxs[2],NULL);
    ck_assert_ptr_ne(ctxs[2]->svids,NULL);
    ck_assert_int_eq(arrlen(ctxs[2]->svids),1);

    ck_assert_ptr_ne(ctxs[3],NULL);
    ck_assert_ptr_ne(ctxs[3]->svids,NULL);
    ck_assert_int_eq(arrlen(ctxs[3]->svids),2);

    // free(ctx);

    // ck_assert_ptr_ne(ctx->Bundles,NULL);
    // ck_assert_str_eq(ctx->svids[0]->id.td.name,"example.org");
    delete stub;
    // free(ctx);
}
END_TEST

Suite* client_suite(void)
{
    Suite *s = suite_create("client");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_workloadapi_parseX509Bundles);
    tcase_add_test(tc_core, test_workloadapi_parseX509Context);
    tcase_add_test(tc_core, test_workloadapi_NewClient);
    tcase_add_test(tc_core, test_workloadapi_Client_Connect_uses_stub);
    tcase_add_test(tc_core, test_workloadapi_Client_Close);
    tcase_add_test(tc_core, test_workloadapi_Client_FetchX509Context);
    tcase_add_test(tc_core, test_workloadapi_Client_WatchX509Context);

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
