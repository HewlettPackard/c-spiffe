#include <check.h>
#include <openssl/pem.h>
#include <stdlib.h>

#define STB_DS_IMPLEMENTATION
#include "svid/jwtsvid/src/svid.h"

/*
Each test named 'test_jwtsvid_<function name>' tests
jwtsvid_<function name> function.
*/

// precondition: valid jwt token
// postcondition: valid jwt svid corresponding to the
// token without claims map
START_TEST(test_jwtsvid_parse)
{
    // spiffeid_TrustDomain td = {"example.com"};
    // jwtbundle_Bundle *bundle = jwtbundle_Load(td,
    // "./resources/jwk_keys.json", &err);

    char token[]
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
    err_t err;
    jwtsvid_SVID *svid = jwtsvid_parse(token, NULL, NULL, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_eq(svid->audience, NULL);
    ck_assert_ptr_eq(svid->claims, NULL);
    ck_assert_int_eq(svid->expiry, 1620000000);
    ck_assert_ptr_ne(svid->id.path, NULL);
    ck_assert_str_eq(svid->id.path, "/workload1");
    ck_assert_ptr_ne(svid->id.td.name, NULL);
    ck_assert_str_eq(svid->id.td.name, "example.com");
    ck_assert_ptr_ne(svid->token, NULL);
    ck_assert_str_eq(svid->token, token);

    jwtsvid_SVID_Free(svid);
}
END_TEST

// precondition: valid jwt token
// postcondition: valid jwt svid corresponding to the
// token with valid claims map
START_TEST(test_jwtsvid_ParseInsecure)
{
    // spiffeid_TrustDomain td = {"example.com"};
    // jwtbundle_Bundle *bundle = jwtbundle_Load(td,
    // "./resources/jwk_keys.json", &err);

    char token[]
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
    err_t err;
    jwtsvid_SVID *svid = jwtsvid_ParseInsecure(token, NULL, &err);

    ck_assert_uint_eq(err, NO_ERROR);
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
    ck_assert_str_eq(svid->token, token);

    jwtsvid_SVID_Free(svid);
}
END_TEST

// precondition: valid jwt token
// postcondition: valid jwt svid corresponding to the
// token with valid claims map and correctly verified signature
START_TEST(test_jwtsvid_ParseAndValidate)
{
    spiffeid_TrustDomain td = { "example.com" };
    jwtbundle_Bundle *bundle = jwtbundle_New(td);

    FILE *f = fopen("./resources/privkey.pem", "r");
    EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);

    err_t err = jwtbundle_Bundle_AddJWTAuthority(
        bundle, "ff3c5c96-392e-46ef-a839-6ff16027af78", pkey);

    ck_assert_uint_eq(err, NO_ERROR);

    char token[]
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
    jwtbundle_Source *source = jwtbundle_SourceFromBundle(bundle);
    jwtsvid_SVID *svid = jwtsvid_ParseAndValidate(token, source, NULL, &err);

    ck_assert_uint_eq(err, NO_ERROR);
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
    ck_assert_str_eq(svid->token, token);

    jwtbundle_Source_Free(source);
    EVP_PKEY_free(pkey);
    jwtsvid_SVID_Free(svid);
}
END_TEST

// precondition:
// postcondition:
START_TEST(test_jwtsvid_EC)
{
    spiffeid_TrustDomain td = { "example.com" };
    jwtbundle_Bundle *bundle = jwtbundle_New(td);

    FILE *f = fopen("./resources/ec-secp256k1-priv-key.pem", "r");
    ck_assert_ptr_ne(f, NULL);
    EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);

    err_t err = jwtbundle_Bundle_AddJWTAuthority(
        bundle, "ff3c5c96-392e-46ef-a839-6ff16027af78", pkey);

    ck_assert_uint_eq(err, NO_ERROR);

    char token[]
        = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImZmM2M1Yzk2LTM5MmUtNDZlZi1hODM5LTZmZjE2MDI3YWY3OCJ9.eyJzdWIiOiJzcGlmZmU6Ly9leGFtcGxlLmNvbS93b3JrbG9hZDEiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTYyMDAwMDAwMH0.WA7x2GiNZvh5BoLkvS7BBGIHz6ULTCsX7DBJo8kDoPla4wbo4G2157WWCZLx6zPE8Qpvvb11kMk0Ivk_G0gMeA";
    jwtbundle_Source *source = jwtbundle_SourceFromBundle(bundle);
    jwtsvid_SVID *svid = jwtsvid_ParseAndValidate(token, source, NULL, &err);

    ck_assert_uint_eq(err, NO_ERROR);
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
    ck_assert_str_eq(svid->token, token);

    jwtbundle_Source_Free(source);
    EVP_PKEY_free(pkey);
    jwtsvid_SVID_Free(svid);

}
END_TEST

START_TEST(test_jwtsvid_Marshal)
    spiffeid_TrustDomain td = { "example.com" };
    jwtbundle_Bundle *bundle = jwtbundle_New(td);

    FILE *f = fopen("./resources/ec-secp256k1-priv-key.pem", "r");
    ck_assert_ptr_ne(f, NULL);
    EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);

    err_t err = jwtbundle_Bundle_AddJWTAuthority(
        bundle, "ff3c5c96-392e-46ef-a839-6ff16027af78", pkey);

    ck_assert_uint_eq(err, NO_ERROR);

    char token[]
        = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImZmM2M1Yzk2LTM5MmUtNDZlZi1hODM5LTZmZjE2MDI3YWY3OCJ9.eyJzdWIiOiJzcGlmZmU6Ly9leGFtcGxlLmNvbS93b3JrbG9hZDEiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTYyMDAwMDAwMH0.WA7x2GiNZvh5BoLkvS7BBGIHz6ULTCsX7DBJo8kDoPla4wbo4G2157WWCZLx6zPE8Qpvvb11kMk0Ivk_G0gMeA";
    jwtbundle_Source *source = jwtbundle_SourceFromBundle(bundle);
    jwtsvid_SVID *svid = jwtsvid_ParseAndValidate(token, source, NULL, &err);

    ck_assert_uint_eq(err, NO_ERROR);
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
    ck_assert_str_eq(svid->token, token);

    const char *marshal = jwtsvid_SVID_Marshal(svid);

    ck_assert_ptr_ne(marshal, NULL);

    jwtbundle_Source_Free(source);
    EVP_PKEY_free(pkey);
    jwtsvid_SVID_Free(svid);
END_TEST

Suite *svid_suite(void)
{
    Suite *s = suite_create("svid");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_jwtsvid_parse);
    tcase_add_test(tc_core, test_jwtsvid_ParseInsecure);
    tcase_add_test(tc_core, test_jwtsvid_ParseAndValidate);
    tcase_add_test(tc_core, test_jwtsvid_EC);
    tcase_add_test(tc_core, test_jwtsvid_Marshal);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    Suite *s = svid_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
