#include "c-spiffe/spiffeid/match.h"
#include "c-spiffe/spiffeid/trustdomain.h"
#include <check.h>

START_TEST(test_spiffeid_MatchAny)
{
    spiffeid_Matcher *m = spiffeid_MatchAny();

    ck_assert_uint_eq(m->type, MATCH_ANY);
    ck_assert(m->ids == NULL);
    ck_assert(m->td.name == NULL);

    spiffeid_Matcher_Free(m);
}
END_TEST

START_TEST(test_spiffeid_MatchID)
{
    err_t err;
    spiffeid_ID id = spiffeid_FromString("spiffe://example.com/path1", &err);
    spiffeid_Matcher *m = spiffeid_MatchID(id);

    ck_assert_uint_eq(err, 0);
    ck_assert_uint_eq(m->type, MATCH_ONEOF);
    ck_assert(m->ids != NULL);
    ck_assert_uint_eq(arrlenu(m->ids), 1);
    ck_assert_str_eq(m->ids[0].td.name, "example.com");
    ck_assert_str_eq(m->ids[0].path, "/path1");
    ck_assert(m->td.name == NULL);

    spiffeid_ID_Free(&id);
    spiffeid_Matcher_Free(m);
}
END_TEST

START_TEST(test_spiffeid_MatchOneOf)
{
    err_t err0, err1, err2;
    spiffeid_ID id0
        = spiffeid_FromString("spiffe://example0.com/path3", &err0);
    spiffeid_ID id1
        = spiffeid_FromString("spiffe://example1.com/path4", &err1);
    spiffeid_ID id2
        = spiffeid_FromString("spiffe://example2.com/path5", &err2);
    spiffeid_Matcher *m = spiffeid_MatchOneOf(3, id0, id1, id2);

    ck_assert_uint_eq(err0, 0);
    ck_assert_uint_eq(err1, 0);
    ck_assert_uint_eq(err2, 0);
    ck_assert_uint_eq(m->type, MATCH_ONEOF);
    ck_assert(m->ids != NULL);
    ck_assert_uint_eq(arrlenu(m->ids), 3);
    ck_assert_str_eq(m->ids[0].td.name, "example0.com");
    ck_assert_str_eq(m->ids[0].path, "/path3");
    ck_assert_str_eq(m->ids[1].td.name, "example1.com");
    ck_assert_str_eq(m->ids[1].path, "/path4");
    ck_assert_str_eq(m->ids[2].td.name, "example2.com");
    ck_assert_str_eq(m->ids[2].path, "/path5");
    ck_assert(m->td.name == NULL);

    spiffeid_ID_Free(&id0);
    spiffeid_ID_Free(&id1);
    spiffeid_ID_Free(&id2);
    spiffeid_Matcher_Free(m);
}
END_TEST

START_TEST(test_spiffeid_MatchMemberOf)
{
    err_t err;
    spiffeid_TrustDomain td
        = spiffeid_TrustDomainFromString("spiffe://example.com", &err);
    spiffeid_Matcher *m = spiffeid_MatchMemberOf(td);

    ck_assert_uint_eq(err, 0);
    ck_assert_uint_eq(m->type, MATCH_MEMBEROF);
    ck_assert(m->ids == NULL);
    ck_assert_str_eq(m->td.name, "example.com");

    spiffeid_TrustDomain_Free(&td);
    spiffeid_Matcher_Free(m);
}
END_TEST

START_TEST(test_spiffeid_ApplyMatcher)
{
    err_t err0, err1, err2, err3;
    spiffeid_ID id10, id20, id21, id22;

    // match any
    spiffeid_Matcher *m0 = spiffeid_MatchAny();

    // match id
    id10 = spiffeid_FromString("spiffe://example.com/path1", &err1);
    spiffeid_Matcher *m1 = spiffeid_MatchID(id10);

    // match one of
    id20 = spiffeid_FromString("spiffe://example0.com/path3", &err0);
    id21 = spiffeid_FromString("spiffe://example1.com/path4", &err1);
    id22 = spiffeid_FromString("spiffe://example2.com/path5", &err2);
    spiffeid_Matcher *m2 = spiffeid_MatchOneOf(3, id20, id21, id22);

    // match trust domain
    spiffeid_TrustDomain td3
        = spiffeid_TrustDomainFromString("spiffe://example.com", &err3);
    spiffeid_Matcher *m3 = spiffeid_MatchMemberOf(td3);

    // apply matcher
    ck_assert(spiffeid_ApplyMatcher(m0, id10) == MATCH_OK);
    ck_assert(spiffeid_ApplyMatcher(m0, id20) == MATCH_OK);
    ck_assert(spiffeid_ApplyMatcher(m0, id21) == MATCH_OK);
    ck_assert(spiffeid_ApplyMatcher(m0, id22) == MATCH_OK);

    ck_assert(spiffeid_ApplyMatcher(m1, id10) == MATCH_OK);
    ck_assert(spiffeid_ApplyMatcher(m1, id20) == MATCH_UNEXPECTED_ID);
    ck_assert(spiffeid_ApplyMatcher(m1, id21) == MATCH_UNEXPECTED_ID);
    ck_assert(spiffeid_ApplyMatcher(m1, id22) == MATCH_UNEXPECTED_ID);

    ck_assert(spiffeid_ApplyMatcher(m2, id10) == MATCH_UNEXPECTED_ID);
    ck_assert(spiffeid_ApplyMatcher(m2, id20) == MATCH_OK);
    ck_assert(spiffeid_ApplyMatcher(m2, id21) == MATCH_OK);
    ck_assert(spiffeid_ApplyMatcher(m2, id22) == MATCH_OK);

    ck_assert(spiffeid_ApplyMatcher(m3, id10) == MATCH_OK);
    ck_assert(spiffeid_ApplyMatcher(m3, id20) == MATCH_UNEXPECTED_TD);
    ck_assert(spiffeid_ApplyMatcher(m3, id21) == MATCH_UNEXPECTED_TD);
    ck_assert(spiffeid_ApplyMatcher(m3, id22) == MATCH_UNEXPECTED_TD);
}
END_TEST

Suite *match_suite(void)
{
    Suite *s = suite_create("match");
    TCase *tc_core = tcase_create("core");

    suite_add_tcase(s, tc_core);

    tcase_add_test(tc_core, test_spiffeid_MatchAny);
    tcase_add_test(tc_core, test_spiffeid_MatchID);
    tcase_add_test(tc_core, test_spiffeid_MatchOneOf);
    tcase_add_test(tc_core, test_spiffeid_MatchMemberOf);
    tcase_add_test(tc_core, test_spiffeid_ApplyMatcher);

    return s;
}

int main(void)
{
    Suite *s = match_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
