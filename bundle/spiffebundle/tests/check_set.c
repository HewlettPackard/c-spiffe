#include "c-spiffe/bundle/spiffebundle/set.h"
#include <check.h>

START_TEST(test_spiffebundle_NewSet)
{
    const int ITERS = 2;

    spiffeid_TrustDomain td[] = { "example.com", "example.org" };
    err_t err;
    spiffebundle_Bundle *bundles[ITERS];
    bundles[0]
        = spiffebundle_Load(td[0], "./resources/jwks_valid_1.json", &err);
    bundles[1]
        = spiffebundle_Load(td[1], "./resources/jwks_valid_2.json", &err);
    spiffebundle_Set *set = spiffebundle_NewSet(2, bundles[0], bundles[1]);

    ck_assert_uint_eq(shlenu(set->bundles), ITERS);
    for(int i = 0; i < ITERS; ++i) {
        ck_assert_int_ge(shgeti(set->bundles, td[i].name), 0);
    }

    spiffebundle_Set_Free(set);
}
END_TEST

START_TEST(test_spiffebundle_Set_Add)
{
    const int ITERS = 2;

    spiffeid_TrustDomain td[] = { "example.com", "example.org" };
    err_t err;
    spiffebundle_Bundle *bundles[ITERS];
    bundles[0]
        = spiffebundle_Load(td[0], "./resources/jwks_valid_1.json", &err);
    bundles[1]
        = spiffebundle_Load(td[1], "./resources/jwks_valid_2.json", &err);
    spiffebundle_Set *set = spiffebundle_NewSet(0);

    ck_assert_uint_eq(shlenu(set->bundles), 0);
    ck_assert(!spiffebundle_Set_Has(set, td[0]));
    ck_assert(!spiffebundle_Set_Has(set, td[1]));

    spiffebundle_Set_Add(set, bundles[0]);
    ck_assert_uint_eq(shlenu(set->bundles), 1);
    ck_assert(spiffebundle_Set_Has(set, td[0]));
    ck_assert(!spiffebundle_Set_Has(set, td[1]));

    spiffebundle_Set_Add(set, bundles[1]);
    ck_assert_uint_eq(shlenu(set->bundles), 2);
    ck_assert(spiffebundle_Set_Has(set, td[0]));
    ck_assert(spiffebundle_Set_Has(set, td[1]));

    spiffebundle_Set_Free(set);
}
END_TEST

START_TEST(test_spiffebundle_Set_Remove)
{
    const int ITERS = 2;

    spiffeid_TrustDomain td[] = { "example.com", "example.org" };
    err_t err;
    spiffebundle_Bundle *bundles[ITERS];
    bundles[0]
        = spiffebundle_Load(td[0], "./resources/jwks_valid_1.json", &err);
    bundles[1]
        = spiffebundle_Load(td[1], "./resources/jwks_valid_2.json", &err);
    spiffebundle_Set *set = spiffebundle_NewSet(2, bundles[0], bundles[1]);

    spiffebundle_Set_Remove(set, td[0]);
    ck_assert_uint_eq(shlenu(set->bundles), 1);
    ck_assert(!spiffebundle_Set_Has(set, td[0]));
    ck_assert(spiffebundle_Set_Has(set, td[1]));

    spiffebundle_Set_Remove(set, td[1]);
    ck_assert_uint_eq(shlenu(set->bundles), 0);
    ck_assert(!spiffebundle_Set_Has(set, td[0]));
    ck_assert(!spiffebundle_Set_Has(set, td[1]));

    for(int i = 0; i < ITERS; ++i) {
        spiffebundle_Bundle_Free(bundles[i]);
    }
    spiffebundle_Set_Free(set);
}
END_TEST

START_TEST(test_spiffebundle_Set_Get)
{
    const int ITERS = 2;

    spiffeid_TrustDomain td[] = { "example.com", "example.org" };
    err_t err;
    spiffebundle_Bundle *bundles[ITERS];
    bundles[0]
        = spiffebundle_Load(td[0], "./resources/jwks_valid_1.json", &err);
    bundles[1]
        = spiffebundle_Load(td[1], "./resources/jwks_valid_2.json", &err);
    spiffebundle_Set *set = spiffebundle_NewSet(2, bundles[0], bundles[1]);

    bool suc;
    spiffebundle_Bundle *bundle = spiffebundle_Set_Get(set, td[0], &suc);
    ck_assert(suc);
    ck_assert(spiffebundle_Bundle_Equal(bundle, bundles[0]));

    bundle = spiffebundle_Set_Get(set, td[1], &suc);
    ck_assert(suc);
    ck_assert(spiffebundle_Bundle_Equal(bundle, bundles[1]));

    bundle = spiffebundle_Set_Get(set, (spiffeid_TrustDomain){ "example.edu" },
                                  &suc);
    ck_assert(!suc);
    ck_assert_ptr_eq(bundle, NULL);

    spiffebundle_Set_Free(set);
}
END_TEST

START_TEST(test_spiffebundle_Set_Bundles)
{
    const int ITERS = 2;

    spiffeid_TrustDomain td[] = { "example.com", "example.org" };
    err_t err;
    spiffebundle_Bundle *bundles[ITERS];
    bundles[0]
        = spiffebundle_Load(td[0], "./resources/jwks_valid_1.json", &err);
    bundles[1]
        = spiffebundle_Load(td[1], "./resources/jwks_valid_2.json", &err);
    spiffebundle_Set *set = spiffebundle_NewSet(2, bundles[0], bundles[1]);
    spiffebundle_Bundle **arr_bundles = spiffebundle_Set_Bundles(set);

    ck_assert_ptr_ne(bundles, NULL);
    ck_assert_uint_eq(arrlenu(bundles), spiffebundle_Set_Len(set));

    spiffebundle_Set_Free(set);
    arrfree(arr_bundles);
}
END_TEST

START_TEST(test_spiffebundle_Set_GetBundleForTrustDomain)
{
    const int ITERS = 2;

    spiffeid_TrustDomain td[] = { "example.com", "example.org" };
    err_t err;
    spiffebundle_Bundle *bundles[ITERS];
    bundles[0]
        = spiffebundle_Load(td[0], "./resources/jwks_valid_1.json", &err);
    bundles[1]
        = spiffebundle_Load(td[1], "./resources/jwks_valid_2.json", &err);
    spiffebundle_Set *set = spiffebundle_NewSet(2, bundles[0], bundles[1]);

    spiffebundle_Bundle *bundle
        = spiffebundle_Set_GetBundleForTrustDomain(set, td[0], &err);
    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert(spiffebundle_Bundle_Equal(bundle, bundles[0]));

    bundle = spiffebundle_Set_GetBundleForTrustDomain(set, td[1], &err);
    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert(spiffebundle_Bundle_Equal(bundle, bundles[1]));

    bundle = spiffebundle_Set_GetBundleForTrustDomain(
        set, (spiffeid_TrustDomain){ "example.edu" }, &err);
    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert_ptr_eq(bundle, NULL);

    spiffebundle_Set_Free(set);
}
END_TEST

START_TEST(test_spiffebundle_Set_GetX509BundleForTrustDomain)
{
    const int ITERS = 2;

    spiffeid_TrustDomain td[] = { "example.com", "example.org" };
    err_t err;
    spiffebundle_Bundle *bundles[ITERS];
    bundles[0]
        = spiffebundle_Load(td[0], "./resources/jwks_valid_1.json", &err);
    bundles[1]
        = spiffebundle_Load(td[1], "./resources/jwks_valid_2.json", &err);
    spiffebundle_Set *set = spiffebundle_NewSet(2, bundles[0], bundles[1]);

    x509bundle_Bundle *x509bundle
        = spiffebundle_Set_GetX509BundleForTrustDomain(set, td[0], &err);
    x509bundle_Bundle *copy_x509bundle
        = spiffebundle_Bundle_X509Bundle(bundles[0]);
    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(x509bundle, NULL);
    ck_assert(x509bundle_Bundle_Equal(x509bundle, copy_x509bundle));
    x509bundle_Bundle_Free(x509bundle);
    x509bundle_Bundle_Free(copy_x509bundle);

    x509bundle
        = spiffebundle_Set_GetX509BundleForTrustDomain(set, td[1], &err);
    copy_x509bundle = spiffebundle_Bundle_X509Bundle(bundles[1]);
    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(x509bundle, NULL);
    ck_assert(x509bundle_Bundle_Equal(x509bundle, copy_x509bundle));
    x509bundle_Bundle_Free(x509bundle);
    x509bundle_Bundle_Free(copy_x509bundle);

    x509bundle = spiffebundle_Set_GetX509BundleForTrustDomain(
        set, (spiffeid_TrustDomain){ "example.edu" }, &err);
    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert_ptr_eq(x509bundle, NULL);

    spiffebundle_Set_Free(set);
}
END_TEST

START_TEST(test_spiffebundle_Set_GetJWTBundleForTrustDomain)
{
    const int ITERS = 2;

    spiffeid_TrustDomain td[] = { "example.com", "example.org" };
    err_t err;
    spiffebundle_Bundle *bundles[ITERS];
    bundles[0]
        = spiffebundle_Load(td[0], "./resources/jwks_valid_1.json", &err);
    bundles[1]
        = spiffebundle_Load(td[1], "./resources/jwks_valid_2.json", &err);
    spiffebundle_Set *set = spiffebundle_NewSet(2, bundles[0], bundles[1]);

    jwtbundle_Bundle *jwtbundle
        = spiffebundle_Set_GetJWTBundleForTrustDomain(set, td[0], &err);
    jwtbundle_Bundle *copy_jwtbundle
        = spiffebundle_Bundle_JWTBundle(bundles[0]);
    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(jwtbundle, NULL);
    ck_assert(jwtbundle_Bundle_Equal(jwtbundle, copy_jwtbundle));
    jwtbundle_Bundle_Free(jwtbundle);
    jwtbundle_Bundle_Free(copy_jwtbundle);

    jwtbundle = spiffebundle_Set_GetJWTBundleForTrustDomain(set, td[1], &err);
    copy_jwtbundle = spiffebundle_Bundle_JWTBundle(bundles[1]);
    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(jwtbundle, NULL);
    ck_assert(jwtbundle_Bundle_Equal(jwtbundle, copy_jwtbundle));
    jwtbundle_Bundle_Free(jwtbundle);
    jwtbundle_Bundle_Free(copy_jwtbundle);

    jwtbundle = spiffebundle_Set_GetJWTBundleForTrustDomain(
        set, (spiffeid_TrustDomain){ "example.edu" }, &err);
    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert_ptr_eq(jwtbundle, NULL);

    spiffebundle_Set_Free(set);
}
END_TEST

Suite *set_suite(void)
{
    Suite *s = suite_create("set");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_spiffebundle_NewSet);
    tcase_add_test(tc_core, test_spiffebundle_Set_Add);
    tcase_add_test(tc_core, test_spiffebundle_Set_Remove);
    tcase_add_test(tc_core, test_spiffebundle_Set_Get);
    tcase_add_test(tc_core, test_spiffebundle_Set_Bundles);
    tcase_add_test(tc_core, test_spiffebundle_Set_GetBundleForTrustDomain);
    tcase_add_test(tc_core, test_spiffebundle_Set_GetX509BundleForTrustDomain);
    tcase_add_test(tc_core, test_spiffebundle_Set_GetJWTBundleForTrustDomain);

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
