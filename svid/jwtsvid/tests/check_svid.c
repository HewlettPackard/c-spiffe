#include <check.h>
#include <openssl/pem.h>
#include <stdlib.h>

#include "c-spiffe/bundle/jwtbundle/source.h"
#include "c-spiffe/svid/jwtsvid/svid.h"
#include "c-spiffe/svid/jwtsvid/parse.h"

// precondition: valid elliptic curve jwt token
// postcondition:  valid jwt svid corresponding
// to the token with valid
START_TEST(test_jwtsvid_Marshal)
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

    char token[] = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImZmM2M1Yzk2LT"
                   "M5MmUtNDZlZi1hODM5LTZmZjE2MDI3YWY3OCJ9."
                   "eyJzdWIiOiJzcGlmZmU6Ly9leGFtcGxlLmNvbS93b3JrbG9hZDEiLCJuYW"
                   "1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6OTk5MDAw"
                   "MDAwMH0.z-azwJt3UzuaL1x0g-"
                   "pGbQOnXXYphAUeBMV3FlVtS53gBBsWLaWWGaJPcLTRdZ50TPTTxh3xlPyv"
                   "P5H-YTP_kQ";
    jwtbundle_Source *source = jwtbundle_SourceFromBundle(bundle);
    jwtsvid_SVID *svid = jwtsvid_ParseAndValidate(token, source, NULL, &err);

    const char *marshal = jwtsvid_SVID_Marshal(svid);

    ck_assert_str_eq(marshal, token);

    jwtbundle_Source_Free(source);
    EVP_PKEY_free(pkey);
    jwtsvid_SVID_Free(svid);
}
END_TEST

Suite *svid_suite(void)
{
    Suite *s = suite_create("svid");
    TCase *tc_core = tcase_create("core");

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
