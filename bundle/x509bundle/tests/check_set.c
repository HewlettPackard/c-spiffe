#include "c-spiffe/internal/cryptoutil/keys.h"
#include "c-spiffe/internal/x509util/util.h"
#include "c-spiffe/spiffeid/trustdomain.h"
#include "c-spiffe/bundle/x509bundle/set.h"
#include <check.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

START_TEST(test_x509bundle_NewSet)
{
    const int ITERS = 3;

    spiffeid_TrustDomain td[]
        = { { "example1.com" }, { "example2.com" }, { "example3.com" } };

    err_t err;
    x509bundle_Bundle *bundle_ptr[ITERS];

    for(int i = 0; i < ITERS; ++i) {
        bundle_ptr[i] = x509bundle_Load(td[i], "./resources/certs.pem", &err);
        ck_assert_uint_eq(err, NO_ERROR);
    }

    x509bundle_Set *set = x509bundle_NewSet(ITERS, bundle_ptr[0],
                                            bundle_ptr[1], bundle_ptr[2]);

    ck_assert_uint_eq(shlenu(set->bundles), ITERS);

    for(int i = 0; i < ITERS; ++i) {
        ck_assert_int_ge(shgeti(set->bundles, td[i].name), 0);
    }

    x509bundle_Set_Free(set);
}
END_TEST

START_TEST(test_x509bundle_Set_Add)
{
    const int ITERS = 3;

    spiffeid_TrustDomain td[]
        = { { "example1.com" }, { "example2.com" }, { "example3.com" } };

    err_t err;
    x509bundle_Bundle *bundle_ptr[ITERS];

    for(int i = 0; i < ITERS; ++i) {
        bundle_ptr[i] = x509bundle_Load(td[i], "./resources/certs.pem", &err);
        ck_assert_uint_eq(err, NO_ERROR);
    }

    x509bundle_Set *set = x509bundle_NewSet(0);

    for(int i = 0; i < ITERS; ++i) {
        x509bundle_Set_Add(set, bundle_ptr[i]);
    }

    ck_assert_uint_eq(shlenu(set->bundles), ITERS);

    for(int i = 0; i < ITERS; ++i) {
        ck_assert_int_ge(shgeti(set->bundles, td[i].name), 0);
    }

    x509bundle_Set_Free(set);
}
END_TEST

START_TEST(test_x509bundle_Set_Remove)
{
    const int ITERS = 3;

    spiffeid_TrustDomain td[]
        = { { "example1.com" }, { "example2.com" }, { "example3.com" } };

    err_t err;
    x509bundle_Bundle *bundle_ptr[ITERS];

    for(int i = 0; i < ITERS; ++i) {
        bundle_ptr[i] = x509bundle_Load(td[i], "./resources/certs.pem", &err);
        ck_assert_uint_eq(err, NO_ERROR);
    }

    x509bundle_Set *set = x509bundle_NewSet(ITERS, bundle_ptr[0],
                                            bundle_ptr[1], bundle_ptr[2]);

    for(int i = 0; i < ITERS; ++i) {
        ck_assert_int_ge(shgeti(set->bundles, td[i].name), 0);
    }

    for(int i = 0; i < ITERS; ++i) {
        x509bundle_Set_Remove(set, td[i]);
        ck_assert_int_lt(shgeti(set->bundles, td[i].name), 0);
        x509bundle_Bundle_Free(bundle_ptr[i]);
    }

    x509bundle_Set_Free(set);
}
END_TEST

START_TEST(test_x509bundle_Set_Has)
{
    const int ITERS = 3;

    spiffeid_TrustDomain td[]
        = { { "example1.com" }, { "example2.com" }, { "example3.com" } };

    err_t err;
    x509bundle_Bundle *bundle_ptr[ITERS];

    for(int i = 0; i < ITERS; ++i) {
        bundle_ptr[i] = x509bundle_Load(td[i], "./resources/certs.pem", &err);
        ck_assert_uint_eq(err, NO_ERROR);
    }

    x509bundle_Set *set = x509bundle_NewSet(0);

    for(int i = 0; i < ITERS; ++i) {
        ck_assert(!x509bundle_Set_Has(set, td[i]));
    }

    for(int i = 0; i < ITERS; ++i) {
        x509bundle_Set_Add(set, bundle_ptr[i]);
    }

    for(int i = 0; i < ITERS; ++i) {
        ck_assert(x509bundle_Set_Has(set, td[i]));
    }

    x509bundle_Set_Free(set);
}
END_TEST

START_TEST(test_x509bundle_Set_Get)
{
    const int ITERS = 3;

    spiffeid_TrustDomain td[]
        = { { "example1.com" }, { "example2.com" }, { "example3.com" } };

    err_t err;
    x509bundle_Bundle *bundle_ptr[ITERS];

    for(int i = 0; i < ITERS; ++i) {
        bundle_ptr[i] = x509bundle_Load(td[i], "./resources/certs.pem", &err);
        ck_assert_uint_eq(err, NO_ERROR);
    }

    x509bundle_Set *set = x509bundle_NewSet(ITERS, bundle_ptr[0],
                                            bundle_ptr[1], bundle_ptr[2]);

    for(int i = 0; i < ITERS; ++i) {
        bool suc;
        x509bundle_Bundle *b = x509bundle_Set_Get(set, td[i], &suc);

        ck_assert(suc);
        ck_assert(b != NULL);
        ck_assert_uint_eq(arrlenu(b->auths), 4);
        ck_assert_int_eq(strcmp(b->td.name, td[i].name), 0);
    }

    spiffeid_TrustDomain newtd = { "example4.com" };
    bool suc;
    x509bundle_Bundle *b = x509bundle_Set_Get(set, newtd, &suc);

    ck_assert(!suc);
    ck_assert(b == NULL);

    x509bundle_Set_Free(set);
}
END_TEST

START_TEST(test_x509bundle_Set_Bundles)
{
    const int ITERS = 3;

    spiffeid_TrustDomain td[]
        = { { "example1.com" }, { "example2.com" }, { "example3.com" } };

    err_t err;
    x509bundle_Bundle *bundle_ptr[ITERS];

    for(int i = 0; i < ITERS; ++i) {
        bundle_ptr[i] = x509bundle_Load(td[i], "./resources/certs.pem", &err);
        ck_assert_uint_eq(err, NO_ERROR);
    }

    x509bundle_Set *set = x509bundle_NewSet(ITERS, bundle_ptr[0],
                                            bundle_ptr[1], bundle_ptr[2]);

    x509bundle_Bundle **bundles = x509bundle_Set_Bundles(set);

    ck_assert_uint_eq(arrlenu(bundles), ITERS);

    for(int i = 0; i < ITERS; ++i) {
        ck_assert_int_eq(strcmp(bundles[i]->td.name, td[i].name), 0);
    }

    x509bundle_Set_Free(set);
}
END_TEST

START_TEST(test_x509bundle_Set_Len)
{
    const int ITERS = 3;

    spiffeid_TrustDomain td[]
        = { { "example1.com" }, { "example2.com" }, { "example3.com" } };

    err_t err;
    x509bundle_Bundle *bundle_ptr[ITERS];

    for(int i = 0; i < ITERS; ++i) {
        bundle_ptr[i] = x509bundle_Load(td[i], "./resources/certs.pem", &err);
        ck_assert_uint_eq(err, NO_ERROR);
    }

    x509bundle_Set *set = x509bundle_NewSet(ITERS, bundle_ptr[0],
                                            bundle_ptr[1], bundle_ptr[2]);

    const uint32_t setlen = x509bundle_Set_Len(set);
    ck_assert_uint_eq(setlen, ITERS);

    x509bundle_Set_Free(set);
}
END_TEST

START_TEST(test_x509bundle_Set_GetX509BundleForTrustDomain)
{
    const int ITERS = 3;

    spiffeid_TrustDomain td[]
        = { { "example1.com" }, { "example2.com" }, { "example3.com" } };

    err_t err;
    x509bundle_Bundle *bundle_ptr[ITERS];

    for(int i = 0; i < ITERS; ++i) {
        bundle_ptr[i] = x509bundle_Load(td[i], "./resources/certs.pem", &err);
        ck_assert_uint_eq(err, NO_ERROR);
    }

    x509bundle_Set *set = x509bundle_NewSet(ITERS, bundle_ptr[0],
                                            bundle_ptr[1], bundle_ptr[2]);

    for(int i = 0; i < ITERS; ++i) {
        x509bundle_Bundle *b
            = x509bundle_Set_GetX509BundleForTrustDomain(set, td[i], &err);

        ck_assert_uint_eq(err, NO_ERROR);
        ck_assert(b != NULL);
        ck_assert_uint_eq(arrlenu(b->auths), 4);
        ck_assert_int_eq(strcmp(b->td.name, td[i].name), 0);
    }

    spiffeid_TrustDomain newtd = { "example4.com" };
    x509bundle_Bundle *b
        = x509bundle_Set_GetX509BundleForTrustDomain(set, newtd, &err);

    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert(b == NULL);

    x509bundle_Set_Free(set);
}
END_TEST

Suite *set_suite(void)
{
    Suite *s = suite_create("set");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_x509bundle_NewSet);
    tcase_add_test(tc_core, test_x509bundle_Set_Add);
    tcase_add_test(tc_core, test_x509bundle_Set_Remove);
    tcase_add_test(tc_core, test_x509bundle_Set_Has);
    tcase_add_test(tc_core, test_x509bundle_Set_Get);
    tcase_add_test(tc_core, test_x509bundle_Set_Bundles);
    tcase_add_test(tc_core, test_x509bundle_Set_Len);
    tcase_add_test(tc_core, test_x509bundle_Set_GetX509BundleForTrustDomain);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    Suite *s = set_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
