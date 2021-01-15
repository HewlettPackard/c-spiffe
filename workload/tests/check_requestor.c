/*
 * Filename: c-spiffe/requestor/requestor.cpp
 * Path: c-spiffe/requestor
 * Created Date: Monday, December 21nd 2020, 10:32:38 am
 * Author: Rodrigo Lopes (rlc2@cesar.org.br)
 * 
 * Copyright (c) 2020 CESAR
 */

#include <check.h>
#include "../src/requestor.h"


START_TEST(test_requestor_init)
{
    //normal constructor test
    const char* addr = "unix:///tmp/agent.sock";
    Requestor* reqtor = RequestorInit(addr);
    
    ck_assert_ptr_nonnull(reqtor);
    ck_assert_ptr_nonnull(reqtor->address);
    ck_assert_ptr_ne(reqtor->address,addr);
    ck_assert_int_eq(strlen(reqtor->address),strlen(addr));
    ck_assert_str_eq(reqtor->address, addr);

    RequestorFree(reqtor);

    //NULL server address test
    
    reqtor = RequestorInit(NULL);

    ck_assert_ptr_null(reqtor);
    
    //no need to free failed requestor

}
END_TEST

START_TEST(test_requestor_free)
{
    const char* addr = "unix:///tmp/agent.sock";
    Requestor* reqtor = RequestorInit(addr);
    
    ck_assert_ptr_nonnull(reqtor);
    ck_assert_ptr_nonnull(reqtor->address);
    RequestorFree(reqtor);
    //TODO add malloc and free counter

}
END_TEST

START_TEST(test_fetch_default_x509)
{
    //TODO use gRPC to fake a SPIRE server
    //Server must always return the same x509 svid.
    const char* address = "unix:///tmp/fake_agent.sock";
    Requestor* reqtor = RequestorInit(address);

    x509svid_SVID* _svid = FetchDefaultX509SVID(reqtor);

    ck_assert_ptr_null(_svid);

    
    RequestorFree(reqtor);
    free(_svid);
}
END_TEST

START_TEST(test_fetch_all_x509)
{
    //TODO use fake gRPC server
    //Server must always return the same x509 svid.
    const char* address = "unix:///tmp/fake_agent.sock";
}
END_TEST


Suite* requestor_suite(void)
{
    Suite *s = suite_create("requestor");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_requestor_init);
    tcase_add_test(tc_core, test_requestor_free);
    // tcase_add_test(tc_core, test_fetch_default_x509);
    // tcase_add_test(tc_core, test_fetch_all_x509);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    Suite *s = requestor_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);
    
    srunner_free(sr);
    
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}