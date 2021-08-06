#include "c-spiffe/spiffeid/trustdomain.h"
#include "c-spiffe/spiffetls/tlsconfig/authorizer.h"
#include <check.h>

START_TEST(test_tlsconfig_AuthorizeAny)
{
    tlsconfig_Authorizer *authorizer = tlsconfig_AuthorizeAny();
    ck_assert_ptr_ne(authorizer, NULL);
    ck_assert_ptr_ne(authorizer->matcher, NULL);

    err_t err;
    spiffeid_ID id1 = spiffeid_FromString("spiffe://example.com/test1", &err);
    ck_assert_uint_eq(err, NO_ERROR);
    spiffeid_ID id2
        = spiffeid_FromString("spiffe://example.org/workload-1", &err);
    ck_assert_uint_eq(err, NO_ERROR);

    match_err_t m = tlsconfig_ApplyAuthorizer(authorizer, id1, NULL);
    ck_assert_uint_eq(m, MATCH_OK);

    m = tlsconfig_ApplyAuthorizer(authorizer, id2, NULL);
    ck_assert_uint_eq(m, MATCH_OK);

    tlsconfig_Authorizer_Free(authorizer);
    spiffeid_ID_Free(&id1);
    spiffeid_ID_Free(&id2);
}
END_TEST

START_TEST(test_tlsconfig_AuthorizeID)
{
    err_t err;
    spiffeid_ID id
        = spiffeid_FromString("spiffe://example.org/workload-1", &err);
    ck_assert_uint_eq(err, NO_ERROR);

    tlsconfig_Authorizer *authorizer = tlsconfig_AuthorizeID(id);
    ck_assert_ptr_ne(authorizer, NULL);
    ck_assert_ptr_ne(authorizer->matcher, NULL);

    match_err_t m = tlsconfig_ApplyAuthorizer(authorizer, id, NULL);
    ck_assert_uint_eq(m, MATCH_OK);

    spiffeid_ID_Free(&id);
    tlsconfig_Authorizer_Free(authorizer);
}
END_TEST

START_TEST(test_tlsconfig_AuthorizeOneOf)
{
    err_t err;
    spiffeid_ID id1 = spiffeid_FromString("spiffe://example.com/test1", &err);
    ck_assert_uint_eq(err, NO_ERROR);
    spiffeid_ID id2
        = spiffeid_FromString("spiffe://example.org/workload-1", &err);
    ck_assert_uint_eq(err, NO_ERROR);
    spiffeid_ID id3
        = spiffeid_FromString("spiffe://example.com/workload-2", &err);
    ck_assert_uint_eq(err, NO_ERROR);

    tlsconfig_Authorizer *authorizer = tlsconfig_AuthorizeOneOf(2, id1, id2);

    ck_assert_ptr_ne(authorizer, NULL);
    ck_assert_ptr_ne(authorizer->matcher, NULL);

    match_err_t m = tlsconfig_ApplyAuthorizer(authorizer, id1, NULL);
    ck_assert_uint_eq(m, MATCH_OK);

    m = tlsconfig_ApplyAuthorizer(authorizer, id2, NULL);
    ck_assert_uint_eq(m, MATCH_OK);

    m = tlsconfig_ApplyAuthorizer(authorizer, id3, NULL);
    ck_assert_uint_eq(m, MATCH_UNEXPECTED_ID);

    spiffeid_ID_Free(&id1);
    spiffeid_ID_Free(&id2);
    spiffeid_ID_Free(&id3);
    tlsconfig_Authorizer_Free(authorizer);
}
END_TEST

START_TEST(test_tlsconfig_AuthorizeMemberOf)
{
    err_t err;
    spiffeid_TrustDomain td = { string_new("example.com") };

    spiffeid_ID id1 = spiffeid_TrustDomain_NewID(td, "/test1");
    spiffeid_ID id2
        = spiffeid_FromString("spiffe://example.org/workload-1", &err);
    ck_assert_uint_eq(err, NO_ERROR);
    spiffeid_ID id3 = spiffeid_TrustDomain_NewID(td, "/workload-2");

    tlsconfig_Authorizer *authorizer = tlsconfig_AuthorizeMemberOf(td);

    match_err_t m = tlsconfig_ApplyAuthorizer(authorizer, id1, NULL);
    ck_assert_uint_eq(m, MATCH_OK);

    m = tlsconfig_ApplyAuthorizer(authorizer, id2, NULL);
    ck_assert_uint_eq(m, MATCH_UNEXPECTED_TD);

    m = tlsconfig_ApplyAuthorizer(authorizer, id3, NULL);
    ck_assert_uint_eq(m, MATCH_OK);

    spiffeid_TrustDomain_Free(&td);
    spiffeid_ID_Free(&id1);
    spiffeid_ID_Free(&id2);
    spiffeid_ID_Free(&id3);
}
END_TEST

Suite *authorizer_suite(void)
{
    Suite *s = suite_create("authorizer");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_tlsconfig_AuthorizeAny);
    tcase_add_test(tc_core, test_tlsconfig_AuthorizeID);
    tcase_add_test(tc_core, test_tlsconfig_AuthorizeOneOf);
    tcase_add_test(tc_core, test_tlsconfig_AuthorizeMemberOf);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    Suite *s = authorizer_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
