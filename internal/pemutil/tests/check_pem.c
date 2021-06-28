#include "c-spiffe/internal/pemutil/pem.h"
#include <check.h>

#include "c-spiffe/utils/stb_ds.h"

START_TEST(test_pemutil_ParseCertificates)
{
    FILE *f = fopen("./resources/good-leaf-and-intermediate.pem", "r");
    ck_assert_ptr_ne(f, NULL);

    byte *buff = FILE_to_bytes(f);
    fclose(f);
    err_t err;
    X509 **certs = pemutil_ParseCertificates(buff, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(certs, NULL);
    ck_assert_uint_eq(arrlenu(certs), 2);

    arrfree(buff);
    for(size_t i = 0, size = arrlenu(certs); i < size; ++i) {
        X509_free(certs[i]);
    }
    arrfree(certs);

    f = fopen("./resources/good-cert-and-key.pem", "r");
    ck_assert_ptr_ne(f, NULL);

    buff = FILE_to_bytes(f);
    fclose(f);
    certs = pemutil_ParseCertificates(buff, &err);

    ck_assert_ptr_eq(certs, NULL);
    ck_assert_uint_ne(err, NO_ERROR);

    arrfree(buff);
}
END_TEST

START_TEST(test_pemutil_ParsePrivateKey)
{
    FILE *f = fopen("./resources/keys.pem", "r");
    ck_assert_ptr_ne(f, NULL);

    byte *buff = FILE_to_bytes(f);
    err_t err;
    EVP_PKEY *pkey = pemutil_ParsePrivateKey(buff, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(pkey, NULL);

    EVP_PKEY_free(pkey);
}
END_TEST

START_TEST(test_pemutil_EncodeCertificates)
{
    const int ITERS = 2;

    const char *buff[] = {
        "-----BEGIN CERTIFICATE-----\n"
        "MIIG4TCCBcmgAwIBAgIQCd0Ux6hVwNaX+SICZIR/jzANBgkqhkiG9w0BAQUFADBm\n"
        "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n"
        "d3cuZGlnaWNlcnQuY29tMSUwIwYDVQQDExxEaWdpQ2VydCBIaWdoIEFzc3VyYW5j\n"
        "ZSBDQS0zMB4XDTEzMDUxNDAwMDAwMFoXDTE2MDUxODEyMDAwMFowYDELMAkGA1UE\n"
        "BhMCQ0ExEDAOBgNVBAgTB0FsYmVydGExEDAOBgNVBAcTB0NhbGdhcnkxGTAXBgNV\n"
        "BAoTEFNBSVQgUG9seXRlY2huaWMxEjAQBgNVBAMMCSouc2FpdC5jYTCCASIwDQYJ\n"
        "KoZIhvcNAQEBBQADggEPADCCAQoCggEBAJv2n5mZfX6NV0jZof1WdXGiY5Q/W0yD\n"
        "T6tUdIYUjgS8GDkeZJYjtwUCMYD2Wo3rF/1ZJ8p9p2WBP1F3CVvjgO+VeA7tLJsf\n"
        "uAr+S8GE1q5tGO9+lPFkBAZkU38FNfBUblvz1imWb6ORXMc++HjUlrUB0nr2Ae8T\n"
        "1I3K0XGArHJyW5utJ5Xm8dNEYCcs6EAXchiViVtcZ2xIlSQMs+AqhqnZXo2Tt1H+\n"
        "f/tQhQJeMTkZ2kklUcnQ1izdTigMgkOvNzW4Oyd9Z0sBbxzUpneeH3nUB5bEv3MG\n"
        "4JJx7cAVPE4rqjVbtm3v0QbCL/X0ZncJiKl7heKWO+j3DnDZS/oliIkCAwEAAaOC\n"
        "A48wggOLMB8GA1UdIwQYMBaAFFDqc4nbKfsQj57lASDU3nmZSIP3MB0GA1UdDgQW\n"
        "BBTk00KEbrhrTuVWBY2cPzTJd1c1BTBkBgNVHREEXTBbggkqLnNhaXQuY2GCB3Nh\n"
        "aXQuY2GCCmNwLnNhaXQuY2GCDmNwLXVhdC5zYWl0LmNhghd1YXQtaW50ZWdyYXRp\n"
        "b24uc2FpdC5jYYIQdWF0LWFwYXMuc2FpdC5jYTAOBgNVHQ8BAf8EBAMCBaAwHQYD\n"
        "VR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMGEGA1UdHwRaMFgwKqAooCaGJGh0\n"
        "dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9jYTMtZzIxLmNybDAqoCigJoYkaHR0cDov\n"
        "L2NybDQuZGlnaWNlcnQuY29tL2NhMy1nMjEuY3JsMIIBxAYDVR0gBIIBuzCCAbcw\n"
        "ggGzBglghkgBhv1sAQEwggGkMDoGCCsGAQUFBwIBFi5odHRwOi8vd3d3LmRpZ2lj\n"
        "ZXJ0LmNvbS9zc2wtY3BzLXJlcG9zaXRvcnkuaHRtMIIBZAYIKwYBBQUHAgIwggFW\n"
        "HoIBUgBBAG4AeQAgAHUAcwBlACAAbwBmACAAdABoAGkAcwAgAEMAZQByAHQAaQBm\n"
        "AGkAYwBhAHQAZQAgAGMAbwBuAHMAdABpAHQAdQB0AGUAcwAgAGEAYwBjAGUAcAB0\n"
        "AGEAbgBjAGUAIABvAGYAIAB0AGgAZQAgAEQAaQBnAGkAQwBlAHIAdAAgAEMAUAAv\n"
        "AEMAUABTACAAYQBuAGQAIAB0AGgAZQAgAFIAZQBsAHkAaQBuAGcAIABQAGEAcgB0\n"
        "AHkAIABBAGcAcgBlAGUAbQBlAG4AdAAgAHcAaABpAGMAaAAgAGwAaQBtAGkAdAAg\n"
        "AGwAaQBhAGIAaQBsAGkAdAB5ACAAYQBuAGQAIABhAHIAZQAgAGkAbgBjAG8AcgBw\n"
        "AG8AcgBhAHQAZQBkACAAaABlAHIAZQBpAG4AIABiAHkAIAByAGUAZgBlAHIAZQBu\n"
        "AGMAZQAuMHsGCCsGAQUFBwEBBG8wbTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3Au\n"
        "ZGlnaWNlcnQuY29tMEUGCCsGAQUFBzAChjlodHRwOi8vY2FjZXJ0cy5kaWdpY2Vy\n"
        "dC5jb20vRGlnaUNlcnRIaWdoQXNzdXJhbmNlQ0EtMy5jcnQwDAYDVR0TAQH/BAIw\n"
        "ADANBgkqhkiG9w0BAQUFAAOCAQEAcl2YI0iMOwx2FOjfoA8ioCtGc5eag8Prawz4\n"
        "FFs9pMFZfD/K8QvPycMSkw7kPtVjmuQWxNtRAvCSIhr/urqNLBO5Omerx8aZYCOz\n"
        "nsmZpymxMt56DBw+KZrWIodsZx5QjVngbE/qIDLmsYgtKczhTCtgEM1h/IHlO3Ho\n"
        "7IXd2Rr4CqeMoM2v+MTV2FYVEYUHJp0EBU/AMuBjPf6YT/WXMNq6fn+WJpxcqwJJ\n"
        "KtBh7c2vRTklahbh1FaiJ0aFJkDH4tasbD69JQ8R2V5OSuGH6Q7EGlpNl+unqtUy\n"
        "KsAL86HvgzF5D51C9TmFXEtXTlPKnjoqn1TC4Rqpqvh+FHWPJQ==\n"
        "-----END CERTIFICATE-----",
        "-----BEGIN CERTIFICATE-----\n"
        "MIIG4TCCBcmgAwIBAgIQCd0Ux6hVwNaX+SICZIR/jzANBgkqhkiG9w0BAQUFADBm\n"
        "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n"
        "d3cuZGlnaWNlcnQuY29tMSUwIwYDVQQDExxEaWdpQ2VydCBIaWdoIEFzc3VyYW5j\n"
        "ZSBDQS0zMB4XDTEzMDUxNDAwMDAwMFoXDTE2MDUxODEyMDAwMFowYDELMAkGA1UE\n"
        "BhMCQ0ExEDAOBgNVBAgTB0FsYmVydGExEDAOBgNVBAcTB0NhbGdhcnkxGTAXBgNV\n"
        "BAoTEFNBSVQgUG9seXRlY2huaWMxEjAQBgNVBAMMCSouc2FpdC5jYTCCASIwDQYJ\n"
        "KoZIhvcNAQEBBQADggEPADCCAQoCggEBAJv2n5mZfX6NV0jZof1WdXGiY5Q/W0yD\n"
        "T6tUdIYUjgS8GDkeZJYjtwUCMYD2Wo3rF/1ZJ8p9p2WBP1F3CVvjgO+VeA7tLJsf\n"
        "uAr+S8GE1q5tGO9+lPFkBAZkU38FNfBUblvz1imWb6ORXMc++HjUlrUB0nr2Ae8T\n"
        "1I3K0XGArHJyW5utJ5Xm8dNEYCcs6EAXchiViVtcZ2xIlSQMs+AqhqnZXo2Tt1H+\n"
        "f/tQhQJeMTkZ2kklUcnQ1izdTigMgkOvNzW4Oyd9Z0sBbxzUpneeH3nUB5bEv3MG\n"
        "4JJx7cAVPE4rqjVbtm3v0QbCL/X0ZncJiKl7heKWO+j3DnDZS/oliIkCAwEAAaOC\n"
        "A48wggOLMB8GA1UdIwQYMBaAFFDqc4nbKfsQj57lASDU3nmZSIP3MB0GA1UdDgQW\n"
        "BBTk00KEbrhrTuVWBY2cPzTJd1c1BTBkBgNVHREEXTBbggkqLnNhaXQuY2GCB3Nh\n"
        "aXQuY2GCCmNwLnNhaXQuY2GCDmNwLXVhdC5zYWl0LmNhghd1YXQtaW50ZWdyYXRp\n"
        "b24uc2FpdC5jYYIQdWF0LWFwYXMuc2FpdC5jYTAOBgNVHQ8BAf8EBAMCBaAwHQYD\n"
        "VR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMGEGA1UdHwRaMFgwKqAooCaGJGh0\n"
        "dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9jYTMtZzIxLmNybDAqoCigJoYkaHR0cDov\n"
        "L2NybDQuZGlnaWNlcnQuY29tL2NhMy1nMjEuY3JsMIIBxAYDVR0gBIIBuzCCAbcw\n"
        "ggGzBglghkgBhv1sAQEwggGkMDoGCCsGAQUFBwIBFi5odHRwOi8vd3d3LmRpZ2lj\n"
        "ZXJ0LmNvbS9zc2wtY3BzLXJlcG9zaXRvcnkuaHRtMIIBZAYIKwYBBQUHAgIwggFW\n"
        "HoIBUgBBAG4AeQAgAHUAcwBlACAAbwBmACAAdABoAGkAcwAgAEMAZQByAHQAaQBm\n"
        "AGkAYwBhAHQAZQAgAGMAbwBuAHMAdABpAHQAdQB0AGUAcwAgAGEAYwBjAGUAcAB0\n"
        "AGEAbgBjAGUAIABvAGYAIAB0AGgAZQAgAEQAaQBnAGkAQwBlAHIAdAAgAEMAUAAv\n"
        "AEMAUABTACAAYQBuAGQAIAB0AGgAZQAgAFIAZQBsAHkAaQBuAGcAIABQAGEAcgB0\n"
        "AHkAIABBAGcAcgBlAGUAbQBlAG4AdAAgAHcAaABpAGMAaAAgAGwAaQBtAGkAdAAg\n"
        "AGwAaQBhAGIAaQBsAGkAdAB5ACAAYQBuAGQAIABhAHIAZQAgAGkAbgBjAG8AcgBw\n"
        "AG8AcgBhAHQAZQBkACAAaABlAHIAZQBpAG4AIABiAHkAIAByAGUAZgBlAHIAZQBu\n"
        "AGMAZQAuMHsGCCsGAQUFBwEBBG8wbTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3Au\n"
        "ZGlnaWNlcnQuY29tMEUGCCsGAQUFBzAChjlodHRwOi8vY2FjZXJ0cy5kaWdpY2Vy\n"
        "dC5jb20vRGlnaUNlcnRIaWdoQXNzdXJhbmNlQ0EtMy5jcnQwDAYDVR0TAQH/BAIw\n"
        "ADANBgkqhkiG9w0BAQUFAAOCAQEAcl2YI0iMOwx2FOjfoA8ioCtGc5eag8Prawz4\n"
        "FFs9pMFZfD/K8QvPycMSkw7kPtVjmuQWxNtRAvCSIhr/urqNLBO5Omerx8aZYCOz\n"
        "nsmZpymxMt56DBw+KZrWIodsZx5QjVngbE/qIDLmsYgtKczhTCtgEM1h/IHlO3Ho\n"
        "7IXd2Rr4CqeMoM2v+MTV2FYVEYUHJp0EBU/AMuBjPf6YT/WXMNq6fn+WJpxcqwJJ\n"
        "KtBh7c2vRTklahbh1FaiJ0aFJkDH4tasbD69JQ8R2V5OSuGH6Q7EGlpNl+unqtUy\n"
        "KsAL86HvgzF5D51C9TmFXEtXTlPKnjoqn1TC4Rqpqvh+FHWPJQ==\n"
        "-----END CERTIFICATE-----"
    };

    BIO *bio_mems[] = { BIO_new_mem_buf((void *) buff[0], -1),
                        BIO_new_mem_buf((void *) buff[1], -1) };

    X509 **certs = NULL;

    for(int i = 0; i < ITERS; ++i) {
        arrput(certs, PEM_read_bio_X509(bio_mems[i], NULL, NULL, NULL));
    }

    err_t err;
    byte **bytes_arr = pemutil_EncodeCertificates(certs, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(bytes_arr, NULL);
    ck_assert_uint_eq(arrlenu(bytes_arr), 2);
    for(size_t i = 0, size = arrlenu(bytes_arr); i < size; ++i) {
        ck_assert_uint_gt(arrlenu(bytes_arr[i]), 0);
    }

    for(size_t i = 0, size = arrlenu(certs); i < size; ++i) {
        X509_free(certs[i]);
    }
    arrfree(certs);

    for(size_t i = 0, size = arrlenu(bytes_arr); i < size; ++i) {
        arrfree(bytes_arr);
    }
    arrfree(bytes_arr);
}
END_TEST

START_TEST(test_pemutil_EncodePrivateKey)
{
    const char privkey[]
        = "-----BEGIN RSA PRIVATE KEY-----\n"
          "MIICXAIBAAKBgQCUibP4fY2PA/sGMKMbU6usuIGcOAqgQjD6c2ylVo05Oz7pgjnE\n"
          "+O0l2MFRUYUGT5KKk/W+0cAXkxaQHE3n8A8X1mHT8eMDmWnzz0PeYjDE8LQmAw8R\n"
          "Y2FnVKFAB36BIjdb5FsZmCk5QYKU5+nWLMqH/j/IR5AyX5wR2SMoslUg2QIDAQAB\n"
          "AoGAeJ1s7638IhLIZtldyRXjRKi6ToFPV50IKodJxOSIXt3WE0V05ZaA84eUSxUY\n"
          "IOzCgRbuqVmnUz1USAdD18AecC8qc7tXTRALLy7q8fxklPwmGPUOvTFmI7gRMUnv\n"
          "cWrq1gySk3SKpj0YmWnuY9Xmd2+xoWLzUeFD1CROY5OTjIECQQDDlp1+Al7+duR0\n"
          "XyMlkWLIk0nIbkQ5zlTAEipzmaeTSOJi6YG3EMMz3AGuZb7tw6HFxWqeg1hyKJ+T\n"
          "cTM3WTdJAkEAwmrCDKE29n3wFOBKsZZFQbDgVOUXCBs2ubEI+ALe1DJU5BlfnrhJ\n"
          "OINRCNgnwSFNbwxDTkDpR6J6Av2ElAvNEQJAV0dVvk5Wj50Ecz2lFHWdLD41taAn\n"
          "B9igDxnMIcvWcK4cf+ENhmCPiwvJIEa8/aLIBNYErvmTtVWVaBkirrc8KQJABr+z\n"
          "+sJB6S6X/fGHRkDkKJKeRvQo54QiUzHdENbwq0cQAVcMJbNZ/1c3oen2/1JLoNY5\n"
          "I+dG8dCnEaGBT65VMQJBAIDqH1Kqs5tb51cpt6h9ot31SUVud5pSML/babwp3pRs\n"
          "1s6poreym4PkAyRug0Dgcj1zVLt25TlOHvrL9r3Swq8=\n"
          "-----END RSA PRIVATE KEY-----";
    BIO *bio_mem = BIO_new_mem_buf((void *) privkey, -1);
    EVP_PKEY *evp_privkey = PEM_read_bio_PrivateKey(bio_mem, NULL, NULL, NULL);

    err_t err;
    byte *encoded_bytes = pemutil_EncodePrivateKey(evp_privkey, &err);

    ck_assert_int_eq(err, NO_ERROR);
    ck_assert(encoded_bytes != NULL);
    ck_assert_uint_gt(arrlenu(encoded_bytes), 0);

    BIO_free(bio_mem);
    EVP_PKEY_free(evp_privkey);
}
END_TEST

Suite *pem_suite(void)
{
    Suite *s = suite_create("pem");
    TCase *tc_core = tcase_create("core");

    suite_add_tcase(s, tc_core);

    tcase_add_test(tc_core, test_pemutil_ParseCertificates);
    tcase_add_test(tc_core, test_pemutil_ParsePrivateKey);
    tcase_add_test(tc_core, test_pemutil_EncodeCertificates);
    tcase_add_test(tc_core, test_pemutil_EncodePrivateKey);

    return s;
}

int main(void)
{
    Suite *s = pem_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
