#include "c-spiffe/spiffeid/trustdomain.h"
#include <check.h>

START_TEST(test_spiffeid_TrustDomainFromString)
{
    const size_t ITERS = 4;
    const char *str_tds[]
        = { "EXAMPLE.com", "spiffe://EXAMPLE.com", "EXAMPLE.com/path1/path2",
            "spiffe://EXAMPLE.com/path1/path2" };

    const char str_res[] = "example.com";

    for(size_t i = 0; i < ITERS; ++i) {
        err_t err;
        spiffeid_TrustDomain td
            = spiffeid_TrustDomainFromString(str_tds[i], &err);
        ck_assert_str_eq(td.name, str_res);
        ck_assert_uint_eq(err, 0);
        spiffeid_TrustDomain_Free(&td);
    }
}
END_TEST

START_TEST(test_spiffeid_TrustDomain_String)
{
    spiffeid_TrustDomain td = { string_new("example.com") };
    const char *str_td = spiffeid_TrustDomain_String(td);

    ck_assert_str_eq(str_td, "example.com");
    spiffeid_TrustDomain_Free(&td);
}
END_TEST

START_TEST(test_spiffeid_TrustDomain_ID)
{
    spiffeid_TrustDomain td = { string_new("example.com") };
    spiffeid_ID id = spiffeid_TrustDomain_ID(td);

    ck_assert_str_eq(id.td.name, "example.com");
    ck_assert_str_eq(id.path, "");

    spiffeid_TrustDomain_Free(&td);
    spiffeid_ID_Free(&id);
}
END_TEST

START_TEST(test_spiffeid_TrustDomain_IDString)
{
    spiffeid_TrustDomain td = { string_new("example.com") };

    string_t str_td = spiffeid_TrustDomain_IDString(td);

    const char *str_res = "spiffe://example.com/";

    ck_assert_str_eq(str_td, str_res);
}
END_TEST

START_TEST(test_spiffeid_TrustDomain_NewID)
{
    spiffeid_TrustDomain td = { string_new("example.com") };
    string_t path = string_new("path1/path2/PATH3");
    spiffeid_ID id = spiffeid_TrustDomain_NewID(td, path);

    ck_assert_str_eq(id.td.name, "example.com");
    ck_assert_str_eq(id.path, "/path1/path2/PATH3");

    util_string_t_Free(path);
    spiffeid_ID_Free(&id);
    spiffeid_TrustDomain_Free(&td);
}
END_TEST

START_TEST(test_spiffeid_TrustDomain_IsZero)
{
    spiffeid_TrustDomain td0 = { NULL };
    spiffeid_TrustDomain td1 = { string_new("") };
    spiffeid_TrustDomain td2 = { string_new("notzero") };

    ck_assert(spiffeid_TrustDomain_IsZero(td0));
    ck_assert(spiffeid_TrustDomain_IsZero(td1));
    ck_assert(!spiffeid_TrustDomain_IsZero(td2));

    spiffeid_TrustDomain_Free(&td0);
    spiffeid_TrustDomain_Free(&td1);
    spiffeid_TrustDomain_Free(&td2);
}
END_TEST

START_TEST(test_spiffeid_TrustDomain_Compare)
{
    spiffeid_TrustDomain td0 = { string_new("example.com") };
    spiffeid_TrustDomain td1 = { string_new("myexample.com") };
    spiffeid_TrustDomain td2 = { string_new("example.com") };

    ck_assert_int_lt(spiffeid_TrustDomain_Compare(td0, td1), 0);
    ck_assert_int_gt(spiffeid_TrustDomain_Compare(td1, td0), 0);
    ck_assert_int_eq(spiffeid_TrustDomain_Compare(td0, td2), 0);

    spiffeid_TrustDomain_Free(&td0);
    spiffeid_TrustDomain_Free(&td1);
    spiffeid_TrustDomain_Free(&td2);
}
END_TEST

Suite *trustdomain_suite(void)
{
    Suite *s = suite_create("id");
    TCase *tc_core = tcase_create("core");

    suite_add_tcase(s, tc_core);

    tcase_add_test(tc_core, test_spiffeid_TrustDomainFromString);
    tcase_add_test(tc_core, test_spiffeid_TrustDomain_String);
    tcase_add_test(tc_core, test_spiffeid_TrustDomain_ID);
    tcase_add_test(tc_core, test_spiffeid_TrustDomain_IDString);
    tcase_add_test(tc_core, test_spiffeid_TrustDomain_NewID);
    tcase_add_test(tc_core, test_spiffeid_TrustDomain_IsZero);
    tcase_add_test(tc_core, test_spiffeid_TrustDomain_Compare);

    return s;
}

int main(void)
{
    Suite *s = trustdomain_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
