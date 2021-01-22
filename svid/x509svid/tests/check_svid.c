#include <check.h>
#include "../src/svid.h"

START_TEST(test_x509svid_Load)
{
    const int ITERS = 2;
    err_t err;
    x509svid_SVID *svid = x509svid_Load("./resources/good-leaf-and-intermediate.pem",
                                        "./resources/key-pkcs8-ecdsa.pem", &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert(svid != NULL);
    ck_assert_uint_eq(arrlenu(svid->certs), ITERS);
    ck_assert(svid->id.td.name != NULL);
    ck_assert(svid->id.path != NULL);
    ck_assert_str_eq(svid->id.td.name, "example.org");
    ck_assert_str_eq(svid->id.path, "/workload-1");
    ck_assert(svid->privateKey != NULL);
    
    x509svid_SVID_Free(svid, true);
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
    ck_assert(svid != NULL);
    ck_assert_uint_eq(arrlenu(svid->certs), ITERS);
    ck_assert(svid->id.td.name != NULL);
    ck_assert(svid->id.path != NULL);
    ck_assert_str_eq(svid->id.td.name, "example.org");
    ck_assert_str_eq(svid->id.path, "/workload-1");
    ck_assert(svid->privateKey != NULL);
    
    arrfree(raw_certs);
    arrfree(raw_key);
    x509svid_SVID_Free(svid, true);
}
END_TEST

START_TEST(test_x509svid_ParseRaw)
{
    const int ITERS = 4;

    FILE *f = fopen("./resources/good-leaf-and-intermediate.pem", "r");
    string_t buffer = FILE_to_string(f);
    fclose(f);

    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, buffer);
    arrfree(buffer);

    unsigned char certs_der_bytes[10000];
    unsigned char *certs_pout = certs_der_bytes;

    X509 **certs = NULL;
    for(int i = 0; i < ITERS; ++i)
    {
        X509 *cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
        if(cert)
        {
            i2d_X509(cert, &certs_pout);
            arrput(certs, cert);
        }
    }

    f = fopen("./resources/key-pkcs8-ecdsa.pem", "r");
    buffer = FILE_to_string(f);
    fclose(f);

    BIO_puts(bio_mem, buffer);
    arrfree(buffer);

    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio_mem, NULL, NULL, NULL);

    unsigned char pkey_der_bytes[10000];
    unsigned char *pkey_pout = pkey_der_bytes;

    i2d_PrivateKey(pkey, &pkey_pout);

    err_t err;
    x509svid_SVID *svid = x509svid_ParseRaw(certs_der_bytes, 
                                            certs_pout - certs_der_bytes,
                                            pkey_der_bytes,
                                            pkey_pout - pkey_der_bytes,
                                            &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(svid, NULL);
    ck_assert(x509util_CertsEqual(certs, svid->certs));

    EC_KEY *ec_key1 = EVP_PKEY_get0_EC_KEY(pkey);
    EC_KEY *ec_key2 = EVP_PKEY_get0_EC_KEY(svid->privateKey);

    const BIGNUM *n1 = EC_KEY_get0_private_key(ec_key1);
    const EC_GROUP *group1 = EC_KEY_get0_group(ec_key1);

    const BIGNUM *n2 = EC_KEY_get0_private_key(ec_key2);
    const EC_GROUP *group2 = EC_KEY_get0_group(ec_key2);

    ck_assert_int_eq(BN_cmp(n1, n2), 0);
    ck_assert_int_eq(EC_GROUP_cmp(group1, group2, NULL), 0);

    for(size_t i = 0, size = arrlenu(certs); i < size; ++i)
    {
        X509_free(certs[i]);
    }
    arrfree(certs);
    EVP_PKEY_free(pkey);
    BIO_free(bio_mem);
    x509svid_SVID_Free(svid, true);
}
END_TEST

START_TEST(test_x509svid_newSVID)
{
    FILE *f = fopen("./resources/good-leaf-and-intermediate.pem", "r");
    const int ITERS = 2;
    string_t buffer = FILE_to_string(f);
    fclose(f);

    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, buffer);
    arrfree(buffer);

    X509 **certs = NULL;    
    do
    {
        X509 *cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
        if(cert)
            arrput(certs, cert);
        else
            break;
    } while(true);

    f = fopen("./resources/key-pkcs8-ecdsa.pem", "r");
    buffer = FILE_to_string(f);
    fclose(f);

    BIO_puts(bio_mem, buffer);
    arrfree(buffer);

    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio_mem, NULL, NULL, NULL);

    ck_assert(certs != NULL);
    ck_assert_uint_eq(arrlenu(certs), ITERS);

    err_t err;
    x509svid_SVID *svid = x509svid_newSVID(certs, pkey, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert(svid != NULL);
    ck_assert_uint_eq(arrlenu(svid->certs), ITERS);
    ck_assert(svid->id.td.name != NULL);
    ck_assert(svid->id.path != NULL);
    ck_assert_str_eq(svid->id.td.name, "example.org");
    ck_assert_str_eq(svid->id.path, "/workload-1");
    ck_assert(svid->privateKey != NULL);
    
    BIO_free(bio_mem);
    for(size_t i = 0, size = arrlenu(certs); i < size; ++i)
    {
        X509_free(certs[i]);
    }
    x509svid_SVID_Free(svid, true);
}
END_TEST

START_TEST(test_x509svid_validateCertificates)
{
    FILE *f = fopen("./resources/good-leaf-and-intermediate.pem", "r");
    const int ITERS = 2;
    string_t buffer = FILE_to_string(f);
    fclose(f);

    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, buffer);
    arrfree(buffer);

    X509 **certs = NULL;    
    do
    {
        X509 *cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
        if(cert)
            arrput(certs, cert);
        else
            break;
    } while(true);

    ck_assert(certs != NULL);
    ck_assert_uint_eq(arrlenu(certs), ITERS);

    err_t err;
    spiffeid_ID id = x509svid_validateCertificates(certs, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert(id.td.name != NULL);
    ck_assert(id.path != NULL);
    ck_assert_str_eq(id.td.name, "example.org");
    ck_assert_str_eq(id.path, "/workload-1");
    
    BIO_free(bio_mem);
    for(size_t i = 0, size = arrlenu(certs); i < size; ++i)
    {
        X509_free(certs[i]);
    }
    spiffeid_ID_Free(&id, false);
}
END_TEST

START_TEST(test_x509svid_validateLeafCertificate)
{
    FILE *f = fopen("./resources/good-leaf-only.pem", "r");
    string_t buffer = FILE_to_string(f);
    fclose(f);

    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, buffer);
    arrfree(buffer);

    X509 *cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);

    ck_assert(cert != NULL);

    err_t err;
    spiffeid_ID id = x509svid_validateLeafCertificate(cert, &err);
    
    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert(id.td.name != NULL);
    ck_assert(id.path != NULL);
    ck_assert_str_eq(id.td.name, "example.org");
    ck_assert_str_eq(id.path, "/workload-1");
    
    BIO_free(bio_mem);
    X509_free(cert);
    spiffeid_ID_Free(&id, false);
}
END_TEST

START_TEST(test_x509svid_validateSigningCertificates)
{
    FILE *f = fopen("./resources/good-leaf-and-intermediate.pem", "r");
    const int ITERS = 2;
    string_t buffer = FILE_to_string(f);
    fclose(f);

    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, buffer);
    arrfree(buffer);

    X509 **certs = NULL;    
    do
    {
        X509 *cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
        if(cert)
            arrput(certs, cert);
        else
            break;
    } while(true);

    ck_assert(certs != NULL);
    ck_assert_uint_eq(arrlenu(certs), ITERS);

    X509 *leaf = certs[0];
    arrdel(certs, 0);

    err_t err;
    x509svid_validateSigningCertificates(certs, &err);

    arrins(certs, 0, leaf);

    ck_assert_uint_eq(err, NO_ERROR);
    
    BIO_free(bio_mem);
    for(size_t i = 0, size = arrlenu(certs); i < size; ++i)
    {
        X509_free(certs[i]);
    }
}
END_TEST

START_TEST(test_x509svid_validateKeyUsage)
{
    FILE *f = fopen("./resources/good-leaf-only.pem", "r");
    string_t buffer = FILE_to_string(f);
    fclose(f);

    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, buffer);
    arrfree(buffer);

    X509 *cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);

    ck_assert(cert != NULL);

    err_t err;
    x509svid_validateKeyUsage(cert, &err);
    
    ck_assert_uint_eq(err, NO_ERROR);
    
    BIO_free(bio_mem);
    X509_free(cert);
}
END_TEST

START_TEST(test_x509svid_validatePrivateKey)
{
    FILE *f = fopen("./resources/good-cert-and-key.pem", "r");
    string_t buffer = FILE_to_string(f);
    fclose(f);

    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, buffer);
    arrfree(buffer);

    X509 *cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio_mem, NULL, NULL, NULL);

    ck_assert(cert != NULL);
    ck_assert(pkey != NULL);

    err_t err;
    EVP_PKEY *signer = x509svid_validatePrivateKey(pkey, cert, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert(signer != NULL);
    
    BIO_free(bio_mem);
    X509_free(cert);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(signer);
}
END_TEST

START_TEST(test_x509svid_keyMatches)
{
    FILE *f = fopen("./resources/good-cert-and-key.pem", "r");
    string_t buffer = FILE_to_string(f);
    fclose(f);

    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, buffer);
    arrfree(buffer);

    X509 *cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio_mem, NULL, NULL, NULL);
    EVP_PKEY *pubkey = X509_get_pubkey(cert);

    ck_assert(cert != NULL);
    ck_assert(pkey != NULL);
    ck_assert(pubkey != NULL);

    err_t err;
    bool suc = x509svid_keyMatches(pkey, pubkey, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert(suc);
    
    BIO_free(bio_mem);
    X509_free(cert);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pubkey);
}
END_TEST

Suite* svid_suite(void)
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
    tcase_add_test(tc_core, test_x509svid_validatePrivateKey);
    tcase_add_test(tc_core, test_x509svid_keyMatches);

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
