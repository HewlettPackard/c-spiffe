/*
 * Filename: c-spiffe/requestor/requestor.cpp
 * Path: c-spiffe/requestor
 * Created Date: Monday, December 21nd 2020, 10:32:38 am
 * Author: Rodrigo Lopes (rlc2@cesar.org.br)
 * 
 * Copyright (c) 2020 CESAR
 */

#include <iostream> //keep at top

#include "../src/requestor.h"
#include <check.h>
#include <grpc/grpc.h>
#include <grpcpp/grpcpp.h>
#include <gmock/gmock.h>
#include <grpcpp/test/mock_stream.h>
#include "workload.pb.h"
#include "workload.grpc.pb.h"
#include "workload_mock.grpc.pb.h"
#include "../../svid/x509svid/src/svid.h"
#include <cstring>
using grpc::testing::MockClientReader;

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SetArgPointee;
using ::testing::WithArg;


START_TEST(test_workloadapi_RequestorInitWithStub)
{
    //normal constructor test
    const char* addr = "unix:///tmp/agent.sock";
    MockSpiffeWorkloadAPIStub* stub = new MockSpiffeWorkloadAPIStub();
    workloadapi_Requestor* reqtor = 
        workloadapi_RequestorInitWithStub(addr,stub);
    
    ck_assert_ptr_ne(reqtor,NULL);
    ck_assert_ptr_ne(reqtor->address,NULL);
    ck_assert_ptr_ne(reqtor->address,addr);//has to be a copy, not the same string
    ck_assert_int_eq(strlen(reqtor->address),strlen(addr));
    ck_assert_str_eq(reqtor->address, addr);

    workloadapi_RequestorFree(reqtor);

    //NULL server address test
    
    reqtor = workloadapi_RequestorInit(NULL);

    ck_assert_ptr_eq(reqtor,NULL);
    
    //no need to free failed requestor

}
END_TEST

START_TEST(test_workloadapi_RequestorFree)
{
    const char *addr = "unix:///tmp/agent.sock";
    workloadapi_Requestor *reqtor = workloadapi_RequestorInit(addr);
    
    ck_assert_ptr_ne(reqtor,NULL);
    ck_assert_ptr_ne(reqtor->address,NULL);
    workloadapi_RequestorFree(reqtor);
}
END_TEST

ACTION(set_single_SVID_response) 
{
    auto new_svid = arg0->mutable_svids()->Add();
    new_svid->set_spiffe_id("spiffe://example.org/workload_test");
    new_svid->set_x509_svid("X509BIN");
    new_svid->set_x509_svid_key("X509KEYBIN");
}

START_TEST(test_workloadapi_FetchDefaultX509SVID)
{
    //mocks the ClientReader class so we can craft the responses
    auto cr = new MockClientReader<X509SVIDResponse>();
    // std::unique_ptr<::grpc::ClientReaderInterface< ::X509SVIDResponse>> cr_ptr(&cr);
    MockSpiffeWorkloadAPIStub mock_stub;

    EXPECT_CALL(*cr, Read(_))
        .WillRepeatedly(DoAll(WithArg<0>(set_single_SVID_response()),Return(true)));
    //   .WillOnce(Return(false));
    EXPECT_CALL(mock_stub, FetchX509SVIDRaw(_,_))
        .WillOnce(Return(cr));

    const char *addr = "unix:///tmp/agent.sock";
    workloadapi_Requestor *reqtor = 
        workloadapi_RequestorInitWithStub(addr, (stub_ptr)&mock_stub);

    x509svid_SVID *svid = workloadapi_FetchDefaultX509SVID(reqtor);
    ck_assert_ptr_eq(svid, NULL);

    workloadapi_RequestorFree(reqtor);
}
END_TEST

ACTION(set_bundle_response) 
{
    auto new_svid = arg0->mutable_svids()->Add();
    new_svid->set_spiffe_id("spiffe://example.org/workload_test");
    new_svid->set_x509_svid("X509BIN");
    new_svid->set_x509_svid_key("X509KEYBIN");
}

START_TEST(test_workloadapi_FetchX509Bundles)
{
    //mocks the ClientReader class so we can craft the responses
    auto cr = new MockClientReader<X509SVIDResponse>();
    // std::unique_ptr<::grpc::ClientReaderInterface< ::X509SVIDResponse>> cr_ptr(&cr);
    MockSpiffeWorkloadAPIStub mock_stub;

    EXPECT_CALL(*cr, Read(_))
        .WillRepeatedly(DoAll(WithArg<0>(set_bundle_response()),Return(false)));
    //   .WillOnce(Return(false));
    EXPECT_CALL(mock_stub, FetchX509SVIDRaw(_,_))
        .WillOnce(Return(cr));

    const char *addr = "unix:///tmp/agent.sock";
    workloadapi_Requestor *reqtor = 
        workloadapi_RequestorInitWithStub(addr, (stub_ptr)&mock_stub);

    x509bundle_Set *set = workloadapi_FetchX509Bundles(reqtor);
    ck_assert_ptr_eq(set, NULL);

    workloadapi_RequestorFree(reqtor);
}
END_TEST

Suite* requestor_suite(void)
{
    Suite *s = suite_create("requestor");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_workloadapi_RequestorInitWithStub);
    tcase_add_test(tc_core, test_workloadapi_RequestorFree);
    tcase_add_test(tc_core, test_workloadapi_FetchDefaultX509SVID);
    tcase_add_test(tc_core, test_workloadapi_FetchX509Bundles);
    // tcase_add_test(tc_core, test_fetch_all_x509);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(int argc, char **argv)
{
    Suite *s = requestor_suite();
    SRunner *sr = srunner_create(s);
    testing::InitGoogleMock(&argc, argv);
    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);
    
    srunner_free(sr);
    
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
