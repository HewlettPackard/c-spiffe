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
#include <check.h>
#include "workload.pb.h"
#include "workload.grpc.pb.h"
#include "../../svid/x509svid/src/svid.h"
#include "../src/client.h"

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

    X509 **certs = NULL;
    for(int i = 0; i < ITERS; ++i)
    {
        X509 *cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
        if(cert)
        {
            i2d_X509(cert, &pout);
            arrput(certs, cert);
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

    err_t err;
    x509bundle_Set *set = workloadapi_parseX509Bundles(&rep, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(set, NULL);
    ck_assert_uint_eq(x509bundle_Set_Len(set), 3);

    x509bundle_Set_Free(set);
}
END_TEST

Suite* client_suite(void)
{
    Suite *s = suite_create("client");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_workloadapi_parseX509Bundles);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(int argc, char **argv)
{
    Suite *s = client_suite();
    SRunner *sr = srunner_create(s);
    // testing::InitGoogleMock(&argc, argv);
    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);
    
    srunner_free(sr);
    
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
