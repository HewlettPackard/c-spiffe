#include "c-spiffe/internal/x509util/util.h"
#include "c-spiffe/svid/x509svid/svid.h"
#include <check.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdlib.h>

START_TEST(test_x509svid_Load)
{
    /** Well formed files for SVID */

    const int ITERS = 2;
    err_t err;
    x509svid_SVID *svid
        = x509svid_Load("./resources/good-leaf-and-intermediate.pem",
                        "./resources/key-pkcs8-ecdsa.pem", &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(svid, NULL);
    ck_assert_uint_eq(arrlenu(svid->certs), ITERS);
    ck_assert_ptr_ne(svid->id.td.name, NULL);
    ck_assert_ptr_ne(svid->id.path, NULL);
    ck_assert_str_eq(svid->id.td.name, "example.org");
    ck_assert_str_eq(svid->id.path, "/workload-1");
    ck_assert_ptr_ne(svid->private_key, NULL);

    x509svid_SVID_Free(svid);

    /** Testing for NULL path on certificates */

    svid = x509svid_Load(NULL, "./resources/key-pkcs8-ecdsa.pem", &err);

    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert_ptr_eq(svid, NULL);

    /** Testing for NULL path on private key */

    svid = x509svid_Load("./resources/good-leaf-and-intermediate.pem", NULL,
                         &err);

    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert_ptr_eq(svid, NULL);
}
END_TEST

START_TEST(test_x509svid_Parse)
{
    FILE *f = fopen("./resources/good-leaf-and-intermediate.pem", "r");
    const int ITERS = 2;
    byte *raw_certs = FILE_to_bytes(f);
    fclose(f);

    f = fopen("./resources/key-pkcs8-ecdsa.pem", "r");
    byte *raw_key = FILE_to_bytes(f);
    fclose(f);

    err_t err;
    x509svid_SVID *svid = x509svid_Parse(raw_certs, raw_key, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(svid, NULL);
    ck_assert_uint_eq(arrlenu(svid->certs), ITERS);
    ck_assert_ptr_ne(svid->id.td.name, NULL);
    ck_assert_ptr_ne(svid->id.path, NULL);
    ck_assert_str_eq(svid->id.td.name, "example.org");
    ck_assert_str_eq(svid->id.path, "/workload-1");
    ck_assert_ptr_ne(svid->private_key, NULL);

    x509svid_SVID_Free(svid);

    svid = x509svid_Parse(NULL, raw_key, &err);

    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert_ptr_eq(svid, NULL);

    svid = x509svid_Parse(raw_certs, NULL, &err);

    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert_ptr_eq(svid, NULL);

    arrfree(raw_certs);
    arrfree(raw_key);
}
END_TEST

START_TEST(test_x509svid_ParseRaw)
{
    const int ITERS = 4;

    FILE *f = fopen("./resources/good-leaf-and-intermediate.pem", "r");
    ck_assert_ptr_ne(f, NULL);

    unsigned char certs_der_bytes[10000];
    unsigned char *certs_pout = certs_der_bytes;

    X509 **certs = NULL;
    for(int i = 0; i < ITERS; ++i) {
        X509 *cert = PEM_read_X509(f, NULL, NULL, NULL);
        if(cert) {
            i2d_X509(cert, &certs_pout);
            arrput(certs, cert);
        }
    }

    fclose(f);
    f = fopen("./resources/key-pkcs8-ecdsa.pem", "r");
    ck_assert_ptr_ne(f, NULL);

    EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);

    unsigned char pkey_der_bytes[10000];
    unsigned char *pkey_pout = pkey_der_bytes;

    i2d_PrivateKey(pkey, &pkey_pout);

    err_t err;
    x509svid_SVID *svid
        = x509svid_ParseRaw(certs_der_bytes, certs_pout - certs_der_bytes,
                            pkey_der_bytes, pkey_pout - pkey_der_bytes, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(svid, NULL);
    ck_assert(x509util_CertsEqual(certs, svid->certs));

    EC_KEY *ec_key1 = EVP_PKEY_get0_EC_KEY(pkey);
    EC_KEY *ec_key2 = EVP_PKEY_get0_EC_KEY(svid->private_key);

    const BIGNUM *n1 = EC_KEY_get0_private_key(ec_key1);
    const EC_GROUP *group1 = EC_KEY_get0_group(ec_key1);

    const BIGNUM *n2 = EC_KEY_get0_private_key(ec_key2);
    const EC_GROUP *group2 = EC_KEY_get0_group(ec_key2);

    ck_assert_int_eq(BN_cmp(n1, n2), 0);
    ck_assert_int_eq(EC_GROUP_cmp(group1, group2, NULL), 0);

    for(size_t i = 0, size = arrlenu(certs); i < size; ++i) {
        X509_free(certs[i]);
    }
    arrfree(certs);
    EVP_PKEY_free(pkey);
    x509svid_SVID_Free(svid);

    svid = x509svid_ParseRaw(NULL, 10, NULL, 10, &err);

    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert_ptr_eq(svid, NULL);
}
END_TEST

START_TEST(test_x509svid_newSVID)
{
    const int ITERS = 2;

    FILE *f = fopen("./resources/good-leaf-and-intermediate.pem", "r");
    ck_assert_ptr_ne(f, NULL);

    // adding certificates to a stb array of X509 objects
    X509 **certs = NULL;
    do {
        X509 *cert = PEM_read_X509(f, NULL, NULL, NULL);
        if(cert)
            arrput(certs, cert);
        else
            break;
    } while(true);

    fclose(f);
    f = fopen("./resources/key-pkcs8-ecdsa.pem", "r");
    ck_assert_ptr_ne(f, NULL);

    // parsing private key to EVP_PKEY object
    EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);

    ck_assert_ptr_ne(certs, NULL);
    ck_assert_uint_eq(arrlenu(certs), ITERS);

    err_t err;
    x509svid_SVID *svid = x509svid_newSVID(certs, pkey, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(svid, NULL);
    ck_assert_uint_eq(arrlenu(svid->certs), ITERS);
    ck_assert_ptr_ne(svid->id.td.name, NULL);
    ck_assert_ptr_ne(svid->id.path, NULL);
    ck_assert_str_eq(svid->id.td.name, "example.org");
    ck_assert_str_eq(svid->id.path, "/workload-1");
    ck_assert_ptr_ne(svid->private_key, NULL);

    x509svid_SVID_Free(svid);
    
    svid = x509svid_newSVID(NULL, pkey, &err);

    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert_ptr_eq(svid, NULL);

    svid = x509svid_newSVID(certs, NULL, &err);

    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert_ptr_eq(svid, NULL);

    for(size_t i = 0, size = arrlenu(certs); i < size; ++i) {
        X509_free(certs[i]);
    }
    EVP_PKEY_free(pkey);
}
END_TEST

START_TEST(test_x509svid_validateCertificates)
{
    /** well formed partial certificate chain */

    const int ITERS = 2;

    FILE *f = fopen("./resources/good-leaf-and-intermediate.pem", "r");
    ck_assert_ptr_ne(f, NULL);

    X509 **certs = NULL;
    do {
        X509 *cert = PEM_read_X509(f, NULL, NULL, NULL);
        if(cert)
            arrput(certs, cert);
        else
            break;
    } while(true);

    fclose(f);
    ck_assert_ptr_ne(certs, NULL);
    ck_assert_uint_eq(arrlenu(certs), ITERS);

    err_t err;
    spiffeid_ID id = x509svid_validateCertificates(certs, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(id.td.name, NULL);
    ck_assert_ptr_ne(id.path, NULL);
    ck_assert_str_eq(id.td.name, "example.org");
    ck_assert_str_eq(id.path, "/workload-1");

    for(size_t i = 0, size = arrlenu(certs); i < size; ++i) {
        X509_free(certs[i]);
    }
    spiffeid_ID_Free(&id);

    /** Testing for NULL chain */

    id = x509svid_validateCertificates(NULL, &err);

    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert_ptr_eq(id.td.name, NULL);
    ck_assert_ptr_eq(id.path, NULL);
}
END_TEST

START_TEST(test_x509svid_validateLeafCertificate)
{
    /** well formed leaf case */
    FILE *f = fopen("./resources/good-leaf-only.pem", "r");
    ck_assert_ptr_ne(f, NULL);

    X509 *cert = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);

    ck_assert_ptr_ne(cert, NULL);

    err_t err;
    spiffeid_ID id = x509svid_validateLeafCertificate(cert, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(id.td.name, NULL);
    ck_assert_ptr_ne(id.path, NULL);
    ck_assert_str_eq(id.td.name, "example.org");
    ck_assert_str_eq(id.path, "/workload-1");

    X509_free(cert);
    spiffeid_ID_Free(&id);

    /** leaf with wrong flags set */
    f = fopen("./resources/wrong-leaf-cert-sign.pem", "r");
    ck_assert_ptr_ne(f, NULL);

    cert = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);

    ck_assert_ptr_ne(cert, NULL);

    id = x509svid_validateLeafCertificate(cert, &err);

    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert_ptr_eq(id.td.name, NULL);
    ck_assert_ptr_eq(id.path, NULL);

    X509_free(cert);

    /** leaf with no valid spiffe ID */
    f = fopen("./resources/wrong-leaf-empty-id.pem", "r");
    ck_assert_ptr_ne(f, NULL);

    cert = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);

    ck_assert_ptr_ne(cert, NULL);

    id = x509svid_validateLeafCertificate(cert, &err);

    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert_ptr_eq(id.td.name, NULL);
    ck_assert_ptr_eq(id.path, NULL);

    X509_free(cert);
}
END_TEST

START_TEST(test_x509svid_validateSigningCertificates)
{
    const int ITERS = 2;
    FILE *f = fopen("./resources/good-leaf-and-intermediate.pem", "r");
    ck_assert_ptr_ne(f, NULL);

    X509 **certs = NULL;
    do {
        X509 *cert = PEM_read_X509(f, NULL, NULL, NULL);
        if(cert)
            arrput(certs, cert);
        else
            break;
    } while(true);
    fclose(f);

    ck_assert_ptr_ne(certs, NULL);
    ck_assert_uint_eq(arrlenu(certs), ITERS);

    X509 *leaf = certs[0];
    arrdel(certs, 0);

    err_t err;
    x509svid_validateSigningCertificates(certs, &err);

    arrins(certs, 0, leaf);
    ck_assert_uint_eq(err, NO_ERROR);

    for(size_t i = 0, size = arrlenu(certs); i < size; ++i) {
        X509_free(certs[i]);
    }
}
END_TEST

START_TEST(test_x509svid_validateKeyUsage)
{
    FILE *f = fopen("./resources/good-leaf-only.pem", "r");
    ck_assert_ptr_ne(f, NULL);

    X509 *cert = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);

    ck_assert_ptr_ne(cert, NULL);

    err_t err;
    x509svid_validateKeyUsage(cert, &err);

    ck_assert_uint_eq(err, NO_ERROR);

    X509_free(cert);
}
END_TEST

START_TEST(test_x509svid_SVID_GetX509SVID)
{
    // GetX509SVID is the x509 Source interface function
    err_t err;
    x509svid_SVID *svid = x509svid_SVID_GetX509SVID(NULL, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_eq(svid, NULL);

    svid = x509svid_Load("./resources/good-leaf-and-intermediate.pem",
                         "./resources/key-pkcs8-ecdsa.pem", &err);
    ck_assert_ptr_ne(svid, NULL);

    x509svid_SVID *new_svid = x509svid_SVID_GetX509SVID(svid, &err);

    ck_assert_ptr_eq(new_svid, svid);
    ck_assert_uint_eq(err, NO_ERROR);

    x509svid_SVID_Free(svid);
}
END_TEST

START_TEST(test_x509svid_validatePrivateKey)
{
    FILE *f = fopen("./resources/good-leaf-only.pem", "r");
    ck_assert_ptr_ne(f, NULL);

    X509 *cert1 = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    ck_assert_ptr_ne(cert1, NULL);

    f = fopen("./resources/key-pkcs8-rsa.pem", "r");
    EVP_PKEY *pkey1 = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    ck_assert_ptr_ne(pkey1, NULL);

    ck_assert_ptr_ne(cert1, NULL);
    ck_assert_ptr_ne(pkey1, NULL);

    err_t err;
    EVP_PKEY *signer1 = x509svid_validatePrivateKey(pkey1, cert1, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(signer1, NULL);

    f = fopen("./resources/good-leaf-and-intermediate.pem", "r");
    ck_assert_ptr_ne(f, NULL);

    X509 *cert2 = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    ck_assert_ptr_ne(cert2, NULL);

    f = fopen("./resources/key-pkcs8-ecdsa.pem", "r");
    ck_assert_ptr_ne(f, NULL);

    EVP_PKEY *pkey2 = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    ck_assert_ptr_ne(pkey2, NULL);

    EVP_PKEY *signer2 = x509svid_validatePrivateKey(pkey2, cert2, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(signer2, NULL);

    EVP_PKEY *signer3 = x509svid_validatePrivateKey(pkey1, cert2, &err);

    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert_ptr_eq(signer3, NULL);

    EVP_PKEY *signer4 = x509svid_validatePrivateKey(pkey2, cert1, &err);

    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert_ptr_eq(signer4, NULL);

    EVP_PKEY *signer5 = x509svid_validatePrivateKey(NULL, cert1, &err);

    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert_ptr_eq(signer5, NULL);

    X509_free(cert1);
    EVP_PKEY_free(pkey1);
    EVP_PKEY_free(signer1);
    X509_free(cert2);
    EVP_PKEY_free(pkey2);
    EVP_PKEY_free(signer2);
}
END_TEST

START_TEST(test_x509svid_keyMatches)
{
    FILE *f = fopen("./resources/good-cert-and-key.pem", "r");
    ck_assert_ptr_ne(f, NULL);

    X509 *cert1 = PEM_read_X509(f, NULL, NULL, NULL);
    EVP_PKEY *pkey1 = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    EVP_PKEY *pubkey1 = X509_get_pubkey(cert1);

    ck_assert_ptr_ne(cert1, NULL);
    ck_assert_ptr_ne(pkey1, NULL);
    ck_assert_ptr_ne(pubkey1, NULL);

    err_t err;
    bool suc = x509svid_keyMatches(pkey1, pubkey1, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert(suc);

    f = fopen("./resources/good-leaf-only.pem", "r");
    ck_assert_ptr_ne(f, NULL);
    X509 *cert2 = PEM_read_X509(f, NULL, NULL, NULL);
    EVP_PKEY *pubkey2 = X509_get_pubkey(cert2);
    fclose(f);

    f = fopen("./resources/key-pkcs8-rsa.pem", "r");
    ck_assert_ptr_ne(f, NULL);
    EVP_PKEY *pkey2 = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);

    ck_assert_ptr_ne(cert2, NULL);
    ck_assert_ptr_ne(pkey2, NULL);
    ck_assert_ptr_ne(pubkey2, NULL);

    suc = x509svid_keyMatches(pkey2, pubkey2, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert(suc);

    suc = x509svid_keyMatches(pkey1, pubkey2, &err);

    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert(!suc);

    suc = x509svid_keyMatches(pkey2, pubkey1, &err);

    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert(!suc);

    X509_free(cert1);
    EVP_PKEY_free(pkey1);
    EVP_PKEY_free(pubkey1);
    X509_free(cert2);
    EVP_PKEY_free(pkey2);
    EVP_PKEY_free(pubkey2);
}
END_TEST

START_TEST(test_x509svid_SVID_GetDefaultX509SVID)
{
    x509svid_SVID *svid = x509svid_SVID_GetDefaultX509SVID(NULL);

    ck_assert_ptr_eq(svid, NULL);
}
END_TEST

Suite *svid_suite(void)
{
    Suite *s = suite_create("svid");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_x509svid_Load);
    tcase_add_test(tc_core, test_x509svid_Parse);
    tcase_add_test(tc_core, test_x509svid_ParseRaw);
    tcase_add_test(tc_core, test_x509svid_newSVID);
    tcase_add_test(tc_core, test_x509svid_validateCertificates);
    tcase_add_test(tc_core, test_x509svid_validateLeafCertificate);
    tcase_add_test(tc_core, test_x509svid_validateSigningCertificates);
    tcase_add_test(tc_core, test_x509svid_validateKeyUsage);
    tcase_add_test(tc_core, test_x509svid_SVID_GetX509SVID);
    tcase_add_test(tc_core, test_x509svid_validatePrivateKey);
    tcase_add_test(tc_core, test_x509svid_keyMatches);
    tcase_add_test(tc_core, test_x509svid_SVID_GetDefaultX509SVID);

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
