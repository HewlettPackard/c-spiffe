#include "c-spiffe/internal/cryptoutil/keys.h"
#include "c-spiffe/internal/x509util/util.h"
#include "c-spiffe/spiffeid/trustdomain.h"
#include "c-spiffe/bundle/x509bundle/bundle.h"
#include <check.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

START_TEST(test_x509bundle_New)
{
    spiffeid_TrustDomain td = { "example.com" };
    x509bundle_Bundle *bundle_ptr = x509bundle_New(td);

    ck_assert(bundle_ptr->auths == NULL);
    ck_assert(!strcmp(bundle_ptr->td.name, "example.com"));

    x509bundle_Bundle_Free(bundle_ptr);
}
END_TEST

START_TEST(test_x509bundle_Parse)
{
    spiffeid_TrustDomain td = { "example.com" };
    err_t err;

    FILE *f = fopen("./resources/certs.pem", "r");
    string_t buffer = FILE_to_string(f);
    fclose(f);

    x509bundle_Bundle *bundle_ptr = x509bundle_Parse(td, buffer, &err);
    arrfree(buffer);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_uint_eq(arrlenu(bundle_ptr->auths), 4);
    for(size_t i = 0, size = arrlenu(bundle_ptr->auths); i < size; ++i) {
        const X509 *cert = bundle_ptr->auths[i];
        ck_assert(cert != NULL);
    }
    ck_assert(!strcmp(bundle_ptr->td.name, "example.com"));

    x509bundle_Bundle_Free(bundle_ptr);
}
END_TEST

START_TEST(test_x509bundle_Load)
{
    spiffeid_TrustDomain td = { "example.com" };
    err_t err;

    x509bundle_Bundle *bundle_ptr
        = x509bundle_Load(td, "./resources/certs.pem", &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_uint_eq(arrlenu(bundle_ptr->auths), 4);
    for(size_t i = 0, size = arrlenu(bundle_ptr->auths); i < size; ++i) {
        const X509 *cert = bundle_ptr->auths[i];
        ck_assert(cert != NULL);
    }
    ck_assert(!strcmp(bundle_ptr->td.name, "example.com"));

    x509bundle_Bundle_Free(bundle_ptr);
}
END_TEST

START_TEST(test_x509bundle_FromX509Authorities)
{
    const int ITERS = 4;
    const char *certs[] = {
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
        "-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBXzCB6gIJANXCDoURTF5MMA0GCSqGSIb3DQEBCwUAMBcxFTATBgNVBAMMDFBF\n"
        "TVVUSUxURVNUMTAeFw0xODA3MTYyMzU5NTZaFw00NTEyMDEyMzU5NTZaMBcxFTAT\n"
        "BgNVBAMMDFBFTVVUSUxURVNUMTB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQDMfDxC\n"
        "DcBTMAjrmo+yNBuYjavI47dPGPrqIXzfAx7L6M2Bg1ZYDaO8xXgc0+7aZZRg7Fe1\n"
        "Gt0EJEourKA6qN0z4gTU5KWZrPLPwPHU75F90jgThdkmHdO7j3lr2MPjsvUCAwEA\n"
        "ATANBgkqhkiG9w0BAQsFAANhAEsa1QiHgPwW0V4VLtRk7xyKIyCo+D0rgQA1qLmW\n"
        "69aMW12GE+sxGo7INDP2bdQGB/udG5V6FnWNTP89VwakKjU4l6LoqtUtncwoGNgT\n"
        "U2aPnxQpNXW7pWdBVSIBhSnptw==\n"
        "-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBXzCB6gIJAMbKbzUVGQTBMA0GCSqGSIb3DQEBCwUAMBcxFTATBgNVBAMMDFBF\n"
        "TVVUSUxURVNUMjAeFw0xODA3MTYyMzU5NDNaFw00NTEyMDEyMzU5NDNaMBcxFTAT\n"
        "BgNVBAMMDFBFTVVUSUxURVNUMjB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQCuUQFO\n"
        "blDXlrJF45Hn86Mb+UAjwnECaaG9Uj7oldNwEwCimhbCQsDYTRzlAFRbdm+S6Lri\n"
        "0KbhKsqDz2V4n3scLnigsLU9pLGGtAF2W/pONUIEBOwsNVL8qGW1oy6A3V0CAwEA\n"
        "ATANBgkqhkiG9w0BAQsFAANhACjrgsP630Mgyj7LDcyV9/tIr+f3ghjyVIyedFQo\n"
        "MJ0if+4o9MKN/7ius4hvI+L6M9aXGyFp/JlRK4p5upqiG6J/vrG3TNPjZMD5wen8\n"
        "/oMJ7lk8yNVYR9zZQgfVzUPlcA==\n"
        "-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBXzCB6gIJANXCDoURTF5MMA0GCSqGSIb3DQEBCwUAMBcxFTATBgNVBAMMDFBF\n"
        "TVVUSUxURVNUMTAeFw0xODA3MTYyMzU5NTZaFw00NTEyMDEyMzU5NTZaMBcxFTAT\n"
        "BgNVBAMMDFBFTVVUSUxURVNUMTB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQDMfDxC\n"
        "DcBTMAjrmo+yNBuYjavI47dPGPrqIXzfAx7L6M2Bg1ZYDaO8xXgc0+7aZZRg7Fe1\n"
        "Gt0EJEourKA6qN0z4gTU5KWZrPLPwPHU75F90jgThdkmHdO7j3lr2MPjsvUCAwEA\n"
        "ATANBgkqhkiG9w0BAQsFAANhAEsa1QiHgPwW0V4VLtRk7xyKIyCo+D0rgQA1qLmW\n"
        "69aMW12GE+sxGo7INDP2bdQGB/udG5V6FnWNTP89VwakKjU4l6LoqtUtncwoGNgT\n"
        "U2aPnxQpNXW7pWdBVSIBhSnptw==\n"
        "-----END CERTIFICATE-----"
    };

    BIO *bio_mems[ITERS];
    for(int i = 0; i < ITERS; ++i) {
        bio_mems[i] = BIO_new_mem_buf((void *) certs[i], -1);
    }

    X509 **x509_auths = NULL;
    for(int i = 0; i < ITERS; ++i) {
        arrput(x509_auths, PEM_read_bio_X509(bio_mems[i], NULL, NULL, NULL));
    }

    spiffeid_TrustDomain td = { "example.com" };
    x509bundle_Bundle *bundle_ptr
        = x509bundle_FromX509Authorities(td, x509_auths);

    ck_assert(x509util_CertsEqual(x509_auths, bundle_ptr->auths));
    ck_assert(!strcmp(bundle_ptr->td.name, "example.com"));

    for(int i = 0; i < ITERS; ++i) {
        BIO_free(bio_mems[i]);
        X509_free(x509_auths[i]);
    }
    arrfree(x509_auths);
    x509bundle_Bundle_Free(bundle_ptr);
}
END_TEST

START_TEST(test_x509bundle_Bundle_X509Authorities)
{
    spiffeid_TrustDomain td = { "example.com" };
    err_t err;

    x509bundle_Bundle *bundle_ptr
        = x509bundle_Load(td, "./resources/certs.pem", &err);
    X509 **x509_auths = x509bundle_Bundle_X509Authorities(bundle_ptr);

    ck_assert(x509util_CertsEqual(x509_auths, bundle_ptr->auths));

    for(size_t i = 0, size = arrlenu(x509_auths); i < size; ++i) {
        X509_free(x509_auths[i]);
    }
    arrfree(x509_auths);
    x509bundle_Bundle_Free(bundle_ptr);
}
END_TEST

START_TEST(test_x509bundle_Bundle_HasX509Authority)
{
    const int ITERS = 4;
    const char *certs[] = {
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
        "-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBXzCB6gIJANXCDoURTF5MMA0GCSqGSIb3DQEBCwUAMBcxFTATBgNVBAMMDFBF\n"
        "TVVUSUxURVNUMTAeFw0xODA3MTYyMzU5NTZaFw00NTEyMDEyMzU5NTZaMBcxFTAT\n"
        "BgNVBAMMDFBFTVVUSUxURVNUMTB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQDMfDxC\n"
        "DcBTMAjrmo+yNBuYjavI47dPGPrqIXzfAx7L6M2Bg1ZYDaO8xXgc0+7aZZRg7Fe1\n"
        "Gt0EJEourKA6qN0z4gTU5KWZrPLPwPHU75F90jgThdkmHdO7j3lr2MPjsvUCAwEA\n"
        "ATANBgkqhkiG9w0BAQsFAANhAEsa1QiHgPwW0V4VLtRk7xyKIyCo+D0rgQA1qLmW\n"
        "69aMW12GE+sxGo7INDP2bdQGB/udG5V6FnWNTP89VwakKjU4l6LoqtUtncwoGNgT\n"
        "U2aPnxQpNXW7pWdBVSIBhSnptw==\n"
        "-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBXzCB6gIJAMbKbzUVGQTBMA0GCSqGSIb3DQEBCwUAMBcxFTATBgNVBAMMDFBF\n"
        "TVVUSUxURVNUMjAeFw0xODA3MTYyMzU5NDNaFw00NTEyMDEyMzU5NDNaMBcxFTAT\n"
        "BgNVBAMMDFBFTVVUSUxURVNUMjB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQCuUQFO\n"
        "blDXlrJF45Hn86Mb+UAjwnECaaG9Uj7oldNwEwCimhbCQsDYTRzlAFRbdm+S6Lri\n"
        "0KbhKsqDz2V4n3scLnigsLU9pLGGtAF2W/pONUIEBOwsNVL8qGW1oy6A3V0CAwEA\n"
        "ATANBgkqhkiG9w0BAQsFAANhACjrgsP630Mgyj7LDcyV9/tIr+f3ghjyVIyedFQo\n"
        "MJ0if+4o9MKN/7ius4hvI+L6M9aXGyFp/JlRK4p5upqiG6J/vrG3TNPjZMD5wen8\n"
        "/oMJ7lk8yNVYR9zZQgfVzUPlcA==\n"
        "-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBXzCB6gIJANXCDoURTF5MMA0GCSqGSIb3DQEBCwUAMBcxFTATBgNVBAMMDFBF\n"
        "TVVUSUxURVNUMTAeFw0xODA3MTYyMzU5NTZaFw00NTEyMDEyMzU5NTZaMBcxFTAT\n"
        "BgNVBAMMDFBFTVVUSUxURVNUMTB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQDMfDxC\n"
        "DcBTMAjrmo+yNBuYjavI47dPGPrqIXzfAx7L6M2Bg1ZYDaO8xXgc0+7aZZRg7Fe1\n"
        "Gt0EJEourKA6qN0z4gTU5KWZrPLPwPHU75F90jgThdkmHdO7j3lr2MPjsvUCAwEA\n"
        "ATANBgkqhkiG9w0BAQsFAANhAEsa1QiHgPwW0V4VLtRk7xyKIyCo+D0rgQA1qLmW\n"
        "69aMW12GE+sxGo7INDP2bdQGB/udG5V6FnWNTP89VwakKjU4l6LoqtUtncwoGNgT\n"
        "U2aPnxQpNXW7pWdBVSIBhSnptw==\n"
        "-----END CERTIFICATE-----"
    };

    BIO *bio_mems[ITERS];
    for(int i = 0; i < ITERS; ++i) {
        bio_mems[i] = BIO_new_mem_buf((void *) certs[i], -1);
    }

    X509 **x509_auths = NULL;
    for(int i = 0; i < ITERS; ++i) {
        arrput(x509_auths, PEM_read_bio_X509(bio_mems[i], NULL, NULL, NULL));
    }

    spiffeid_TrustDomain td = { "example.com" };
    x509bundle_Bundle *bundle_ptr
        = x509bundle_FromX509Authorities(td, x509_auths);

    for(int i = 0; i < ITERS; ++i) {
        ck_assert(
            x509bundle_Bundle_HasX509Authority(bundle_ptr, x509_auths[i]));
    }

    for(int i = 0; i < ITERS; ++i) {
        BIO_free(bio_mems[i]);
        X509_free(x509_auths[i]);
    }
    arrfree(x509_auths);
    x509bundle_Bundle_Free(bundle_ptr);
}
END_TEST

START_TEST(test_x509bundle_Bundle_AddX509Authority)
{
    const int ITERS = 4;
    const char *certs[] = {
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
        "-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBXzCB6gIJANXCDoURTF5MMA0GCSqGSIb3DQEBCwUAMBcxFTATBgNVBAMMDFBF\n"
        "TVVUSUxURVNUMTAeFw0xODA3MTYyMzU5NTZaFw00NTEyMDEyMzU5NTZaMBcxFTAT\n"
        "BgNVBAMMDFBFTVVUSUxURVNUMTB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQDMfDxC\n"
        "DcBTMAjrmo+yNBuYjavI47dPGPrqIXzfAx7L6M2Bg1ZYDaO8xXgc0+7aZZRg7Fe1\n"
        "Gt0EJEourKA6qN0z4gTU5KWZrPLPwPHU75F90jgThdkmHdO7j3lr2MPjsvUCAwEA\n"
        "ATANBgkqhkiG9w0BAQsFAANhAEsa1QiHgPwW0V4VLtRk7xyKIyCo+D0rgQA1qLmW\n"
        "69aMW12GE+sxGo7INDP2bdQGB/udG5V6FnWNTP89VwakKjU4l6LoqtUtncwoGNgT\n"
        "U2aPnxQpNXW7pWdBVSIBhSnptw==\n"
        "-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBXzCB6gIJAMbKbzUVGQTBMA0GCSqGSIb3DQEBCwUAMBcxFTATBgNVBAMMDFBF\n"
        "TVVUSUxURVNUMjAeFw0xODA3MTYyMzU5NDNaFw00NTEyMDEyMzU5NDNaMBcxFTAT\n"
        "BgNVBAMMDFBFTVVUSUxURVNUMjB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQCuUQFO\n"
        "blDXlrJF45Hn86Mb+UAjwnECaaG9Uj7oldNwEwCimhbCQsDYTRzlAFRbdm+S6Lri\n"
        "0KbhKsqDz2V4n3scLnigsLU9pLGGtAF2W/pONUIEBOwsNVL8qGW1oy6A3V0CAwEA\n"
        "ATANBgkqhkiG9w0BAQsFAANhACjrgsP630Mgyj7LDcyV9/tIr+f3ghjyVIyedFQo\n"
        "MJ0if+4o9MKN/7ius4hvI+L6M9aXGyFp/JlRK4p5upqiG6J/vrG3TNPjZMD5wen8\n"
        "/oMJ7lk8yNVYR9zZQgfVzUPlcA==\n"
        "-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBXzCB6gIJANXCDoURTF5MMA0GCSqGSIb3DQEBCwUAMBcxFTATBgNVBAMMDFBF\n"
        "TVVUSUxURVNUMTAeFw0xODA3MTYyMzU5NTZaFw00NTEyMDEyMzU5NTZaMBcxFTAT\n"
        "BgNVBAMMDFBFTVVUSUxURVNUMTB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQDMfDxC\n"
        "DcBTMAjrmo+yNBuYjavI47dPGPrqIXzfAx7L6M2Bg1ZYDaO8xXgc0+7aZZRg7Fe1\n"
        "Gt0EJEourKA6qN0z4gTU5KWZrPLPwPHU75F90jgThdkmHdO7j3lr2MPjsvUCAwEA\n"
        "ATANBgkqhkiG9w0BAQsFAANhAEsa1QiHgPwW0V4VLtRk7xyKIyCo+D0rgQA1qLmW\n"
        "69aMW12GE+sxGo7INDP2bdQGB/udG5V6FnWNTP89VwakKjU4l6LoqtUtncwoGNgT\n"
        "U2aPnxQpNXW7pWdBVSIBhSnptw==\n"
        "-----END CERTIFICATE-----"
    };

    BIO *bio_mems[ITERS];
    for(int i = 0; i < ITERS; ++i) {
        bio_mems[i] = BIO_new_mem_buf((void *) certs[i], -1);
    }

    X509 **x509_auths = NULL;
    for(int i = 0; i < ITERS; ++i) {
        arrput(x509_auths, PEM_read_bio_X509(bio_mems[i], NULL, NULL, NULL));
    }

    spiffeid_TrustDomain td = { "example.com" };
    x509bundle_Bundle *bundle_ptr = x509bundle_New(td);

    for(int i = 0; i < ITERS; ++i) {
        ck_assert(
            !x509bundle_Bundle_HasX509Authority(bundle_ptr, x509_auths[i]));
    }

    for(int i = 0; i < ITERS; ++i) {
        x509bundle_Bundle_AddX509Authority(bundle_ptr, x509_auths[i]);
        ck_assert(
            x509bundle_Bundle_HasX509Authority(bundle_ptr, x509_auths[i]));
    }

    for(int i = 0; i < ITERS; ++i) {
        BIO_free(bio_mems[i]);
        X509_free(x509_auths[i]);
    }
    arrfree(x509_auths);
    x509bundle_Bundle_Free(bundle_ptr);
}
END_TEST

START_TEST(test_x509bundle_Bundle_RemoveX509Authority)
{
    const int ITERS = 4;
    const char *certs[] = {
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
        "-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBXzCB6gIJANXCDoURTF5MMA0GCSqGSIb3DQEBCwUAMBcxFTATBgNVBAMMDFBF\n"
        "TVVUSUxURVNUMTAeFw0xODA3MTYyMzU5NTZaFw00NTEyMDEyMzU5NTZaMBcxFTAT\n"
        "BgNVBAMMDFBFTVVUSUxURVNUMTB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQDMfDxC\n"
        "DcBTMAjrmo+yNBuYjavI47dPGPrqIXzfAx7L6M2Bg1ZYDaO8xXgc0+7aZZRg7Fe1\n"
        "Gt0EJEourKA6qN0z4gTU5KWZrPLPwPHU75F90jgThdkmHdO7j3lr2MPjsvUCAwEA\n"
        "ATANBgkqhkiG9w0BAQsFAANhAEsa1QiHgPwW0V4VLtRk7xyKIyCo+D0rgQA1qLmW\n"
        "69aMW12GE+sxGo7INDP2bdQGB/udG5V6FnWNTP89VwakKjU4l6LoqtUtncwoGNgT\n"
        "U2aPnxQpNXW7pWdBVSIBhSnptw==\n"
        "-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBXzCB6gIJAMbKbzUVGQTBMA0GCSqGSIb3DQEBCwUAMBcxFTATBgNVBAMMDFBF\n"
        "TVVUSUxURVNUMjAeFw0xODA3MTYyMzU5NDNaFw00NTEyMDEyMzU5NDNaMBcxFTAT\n"
        "BgNVBAMMDFBFTVVUSUxURVNUMjB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQCuUQFO\n"
        "blDXlrJF45Hn86Mb+UAjwnECaaG9Uj7oldNwEwCimhbCQsDYTRzlAFRbdm+S6Lri\n"
        "0KbhKsqDz2V4n3scLnigsLU9pLGGtAF2W/pONUIEBOwsNVL8qGW1oy6A3V0CAwEA\n"
        "ATANBgkqhkiG9w0BAQsFAANhACjrgsP630Mgyj7LDcyV9/tIr+f3ghjyVIyedFQo\n"
        "MJ0if+4o9MKN/7ius4hvI+L6M9aXGyFp/JlRK4p5upqiG6J/vrG3TNPjZMD5wen8\n"
        "/oMJ7lk8yNVYR9zZQgfVzUPlcA==\n"
        "-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBXzCB6gIJANXCDoURTF5MMA0GCSqGSIb3DQEBCwUAMBcxFTATBgNVBAMMDFBF\n"
        "TVVUSUxURVNUMTAeFw0xODA3MTYyMzU5NTZaFw00NTEyMDEyMzU5NTZaMBcxFTAT\n"
        "BgNVBAMMDFBFTVVUSUxURVNUMTB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQDMfDxC\n"
        "DcBTMAjrmo+yNBuYjavI47dPGPrqIXzfAx7L6M2Bg1ZYDaO8xXgc0+7aZZRg7Fe1\n"
        "Gt0EJEourKA6qN0z4gTU5KWZrPLPwPHU75F90jgThdkmHdO7j3lr2MPjsvUCAwEA\n"
        "ATANBgkqhkiG9w0BAQsFAANhAEsa1QiHgPwW0V4VLtRk7xyKIyCo+D0rgQA1qLmW\n"
        "69aMW12GE+sxGo7INDP2bdQGB/udG5V6FnWNTP89VwakKjU4l6LoqtUtncwoGNgT\n"
        "U2aPnxQpNXW7pWdBVSIBhSnptw==\n"
        "-----END CERTIFICATE-----"
    };

    BIO *bio_mems[ITERS];
    for(int i = 0; i < ITERS; ++i) {
        bio_mems[i] = BIO_new_mem_buf((void *) certs[i], -1);
    }

    X509 **x509_auths = NULL;
    for(int i = 0; i < ITERS; ++i) {
        arrput(x509_auths, PEM_read_bio_X509(bio_mems[i], NULL, NULL, NULL));
    }

    spiffeid_TrustDomain td = { "example.com" };
    x509bundle_Bundle *bundle_ptr
        = x509bundle_FromX509Authorities(td, x509_auths);

    for(int i = 0; i < ITERS; ++i) {
        ck_assert(
            x509bundle_Bundle_HasX509Authority(bundle_ptr, x509_auths[i]));
    }

    for(int i = 0; i < ITERS; ++i) {
        x509bundle_Bundle_RemoveX509Authority(bundle_ptr, x509_auths[i]);
    }

    for(int i = 0; i < ITERS; ++i) {
        ck_assert(
            !x509bundle_Bundle_HasX509Authority(bundle_ptr, x509_auths[i]));
    }

    for(int i = 0; i < ITERS; ++i) {
        BIO_free(bio_mems[i]);
        X509_free(x509_auths[i]);
    }
    arrfree(x509_auths);
    x509bundle_Bundle_Free(bundle_ptr);
}
END_TEST

START_TEST(test_x509bundle_Bundle_SetX509Authorities)
{
    const int ITERS = 4;
    const char *certs[] = {
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
        "-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBXzCB6gIJANXCDoURTF5MMA0GCSqGSIb3DQEBCwUAMBcxFTATBgNVBAMMDFBF\n"
        "TVVUSUxURVNUMTAeFw0xODA3MTYyMzU5NTZaFw00NTEyMDEyMzU5NTZaMBcxFTAT\n"
        "BgNVBAMMDFBFTVVUSUxURVNUMTB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQDMfDxC\n"
        "DcBTMAjrmo+yNBuYjavI47dPGPrqIXzfAx7L6M2Bg1ZYDaO8xXgc0+7aZZRg7Fe1\n"
        "Gt0EJEourKA6qN0z4gTU5KWZrPLPwPHU75F90jgThdkmHdO7j3lr2MPjsvUCAwEA\n"
        "ATANBgkqhkiG9w0BAQsFAANhAEsa1QiHgPwW0V4VLtRk7xyKIyCo+D0rgQA1qLmW\n"
        "69aMW12GE+sxGo7INDP2bdQGB/udG5V6FnWNTP89VwakKjU4l6LoqtUtncwoGNgT\n"
        "U2aPnxQpNXW7pWdBVSIBhSnptw==\n"
        "-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBXzCB6gIJAMbKbzUVGQTBMA0GCSqGSIb3DQEBCwUAMBcxFTATBgNVBAMMDFBF\n"
        "TVVUSUxURVNUMjAeFw0xODA3MTYyMzU5NDNaFw00NTEyMDEyMzU5NDNaMBcxFTAT\n"
        "BgNVBAMMDFBFTVVUSUxURVNUMjB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQCuUQFO\n"
        "blDXlrJF45Hn86Mb+UAjwnECaaG9Uj7oldNwEwCimhbCQsDYTRzlAFRbdm+S6Lri\n"
        "0KbhKsqDz2V4n3scLnigsLU9pLGGtAF2W/pONUIEBOwsNVL8qGW1oy6A3V0CAwEA\n"
        "ATANBgkqhkiG9w0BAQsFAANhACjrgsP630Mgyj7LDcyV9/tIr+f3ghjyVIyedFQo\n"
        "MJ0if+4o9MKN/7ius4hvI+L6M9aXGyFp/JlRK4p5upqiG6J/vrG3TNPjZMD5wen8\n"
        "/oMJ7lk8yNVYR9zZQgfVzUPlcA==\n"
        "-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBXzCB6gIJANXCDoURTF5MMA0GCSqGSIb3DQEBCwUAMBcxFTATBgNVBAMMDFBF\n"
        "TVVUSUxURVNUMTAeFw0xODA3MTYyMzU5NTZaFw00NTEyMDEyMzU5NTZaMBcxFTAT\n"
        "BgNVBAMMDFBFTVVUSUxURVNUMTB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQDMfDxC\n"
        "DcBTMAjrmo+yNBuYjavI47dPGPrqIXzfAx7L6M2Bg1ZYDaO8xXgc0+7aZZRg7Fe1\n"
        "Gt0EJEourKA6qN0z4gTU5KWZrPLPwPHU75F90jgThdkmHdO7j3lr2MPjsvUCAwEA\n"
        "ATANBgkqhkiG9w0BAQsFAANhAEsa1QiHgPwW0V4VLtRk7xyKIyCo+D0rgQA1qLmW\n"
        "69aMW12GE+sxGo7INDP2bdQGB/udG5V6FnWNTP89VwakKjU4l6LoqtUtncwoGNgT\n"
        "U2aPnxQpNXW7pWdBVSIBhSnptw==\n"
        "-----END CERTIFICATE-----"
    };

    BIO *bio_mems[ITERS];
    for(int i = 0; i < ITERS; ++i) {
        bio_mems[i] = BIO_new_mem_buf((void *) certs[i], -1);
    }

    X509 **x509_auths = NULL;
    for(int i = 0; i < ITERS; ++i) {
        arrput(x509_auths, PEM_read_bio_X509(bio_mems[i], NULL, NULL, NULL));
    }

    spiffeid_TrustDomain td = { "example.com" };
    x509bundle_Bundle *bundle_ptr = x509bundle_New(td);

    for(int i = 0; i < ITERS; ++i) {
        ck_assert(
            !x509bundle_Bundle_HasX509Authority(bundle_ptr, x509_auths[i]));
    }

    x509bundle_Bundle_SetX509Authorities(bundle_ptr, x509_auths);

    for(int i = 0; i < ITERS; ++i) {
        ck_assert(
            x509bundle_Bundle_HasX509Authority(bundle_ptr, x509_auths[i]));
    }

    for(int i = 0; i < ITERS; ++i) {
        BIO_free(bio_mems[i]);
        X509_free(x509_auths[i]);
    }
    arrfree(x509_auths);
    x509bundle_Bundle_Free(bundle_ptr);
}
END_TEST

START_TEST(test_x509bundle_Bundle_Empty)
{
    const int ITERS = 4;
    const char *certs[] = {
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
        "-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBXzCB6gIJANXCDoURTF5MMA0GCSqGSIb3DQEBCwUAMBcxFTATBgNVBAMMDFBF\n"
        "TVVUSUxURVNUMTAeFw0xODA3MTYyMzU5NTZaFw00NTEyMDEyMzU5NTZaMBcxFTAT\n"
        "BgNVBAMMDFBFTVVUSUxURVNUMTB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQDMfDxC\n"
        "DcBTMAjrmo+yNBuYjavI47dPGPrqIXzfAx7L6M2Bg1ZYDaO8xXgc0+7aZZRg7Fe1\n"
        "Gt0EJEourKA6qN0z4gTU5KWZrPLPwPHU75F90jgThdkmHdO7j3lr2MPjsvUCAwEA\n"
        "ATANBgkqhkiG9w0BAQsFAANhAEsa1QiHgPwW0V4VLtRk7xyKIyCo+D0rgQA1qLmW\n"
        "69aMW12GE+sxGo7INDP2bdQGB/udG5V6FnWNTP89VwakKjU4l6LoqtUtncwoGNgT\n"
        "U2aPnxQpNXW7pWdBVSIBhSnptw==\n"
        "-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBXzCB6gIJAMbKbzUVGQTBMA0GCSqGSIb3DQEBCwUAMBcxFTATBgNVBAMMDFBF\n"
        "TVVUSUxURVNUMjAeFw0xODA3MTYyMzU5NDNaFw00NTEyMDEyMzU5NDNaMBcxFTAT\n"
        "BgNVBAMMDFBFTVVUSUxURVNUMjB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQCuUQFO\n"
        "blDXlrJF45Hn86Mb+UAjwnECaaG9Uj7oldNwEwCimhbCQsDYTRzlAFRbdm+S6Lri\n"
        "0KbhKsqDz2V4n3scLnigsLU9pLGGtAF2W/pONUIEBOwsNVL8qGW1oy6A3V0CAwEA\n"
        "ATANBgkqhkiG9w0BAQsFAANhACjrgsP630Mgyj7LDcyV9/tIr+f3ghjyVIyedFQo\n"
        "MJ0if+4o9MKN/7ius4hvI+L6M9aXGyFp/JlRK4p5upqiG6J/vrG3TNPjZMD5wen8\n"
        "/oMJ7lk8yNVYR9zZQgfVzUPlcA==\n"
        "-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBXzCB6gIJANXCDoURTF5MMA0GCSqGSIb3DQEBCwUAMBcxFTATBgNVBAMMDFBF\n"
        "TVVUSUxURVNUMTAeFw0xODA3MTYyMzU5NTZaFw00NTEyMDEyMzU5NTZaMBcxFTAT\n"
        "BgNVBAMMDFBFTVVUSUxURVNUMTB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQDMfDxC\n"
        "DcBTMAjrmo+yNBuYjavI47dPGPrqIXzfAx7L6M2Bg1ZYDaO8xXgc0+7aZZRg7Fe1\n"
        "Gt0EJEourKA6qN0z4gTU5KWZrPLPwPHU75F90jgThdkmHdO7j3lr2MPjsvUCAwEA\n"
        "ATANBgkqhkiG9w0BAQsFAANhAEsa1QiHgPwW0V4VLtRk7xyKIyCo+D0rgQA1qLmW\n"
        "69aMW12GE+sxGo7INDP2bdQGB/udG5V6FnWNTP89VwakKjU4l6LoqtUtncwoGNgT\n"
        "U2aPnxQpNXW7pWdBVSIBhSnptw==\n"
        "-----END CERTIFICATE-----"
    };
    BIO *bio_mems[ITERS];

    for(int i = 0; i < ITERS; ++i) {
        bio_mems[i] = BIO_new_mem_buf((void *) certs[i], -1);
    }

    X509 **x509_auths = NULL;
    for(int i = 0; i < ITERS; ++i) {
        arrput(x509_auths, PEM_read_bio_X509(bio_mems[i], NULL, NULL, NULL));
    }

    spiffeid_TrustDomain td = { "example.com" };
    x509bundle_Bundle *bundle_ptr = x509bundle_New(td);

    ck_assert(x509bundle_Bundle_Empty(bundle_ptr));
    x509bundle_Bundle_AddX509Authority(bundle_ptr, x509_auths[0]);
    ck_assert(!x509bundle_Bundle_Empty(bundle_ptr));
    x509bundle_Bundle_RemoveX509Authority(bundle_ptr, x509_auths[0]);
    ck_assert(x509bundle_Bundle_Empty(bundle_ptr));
    x509bundle_Bundle_AddX509Authority(bundle_ptr, x509_auths[0]);
    x509bundle_Bundle_AddX509Authority(bundle_ptr, x509_auths[1]);
    x509bundle_Bundle_AddX509Authority(bundle_ptr, x509_auths[2]);
    x509bundle_Bundle_AddX509Authority(bundle_ptr, x509_auths[3]);
    ck_assert(!x509bundle_Bundle_Empty(bundle_ptr));
    x509bundle_Bundle_RemoveX509Authority(bundle_ptr, x509_auths[2]);
    x509bundle_Bundle_RemoveX509Authority(bundle_ptr, x509_auths[0]);
    x509bundle_Bundle_RemoveX509Authority(bundle_ptr, x509_auths[1]);
    x509bundle_Bundle_RemoveX509Authority(bundle_ptr, x509_auths[3]);
    ck_assert(x509bundle_Bundle_Empty(bundle_ptr));

    for(int i = 0; i < ITERS; ++i) {
        BIO_free(bio_mems[i]);
        X509_free(x509_auths[i]);
    }
    arrfree(x509_auths);
    x509bundle_Bundle_Free(bundle_ptr);
}
END_TEST

START_TEST(test_x509bundle_Bundle_Equal)
{
    const int ITERS = 4;
    const char *certs[] = {
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
        "-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBXzCB6gIJANXCDoURTF5MMA0GCSqGSIb3DQEBCwUAMBcxFTATBgNVBAMMDFBF\n"
        "TVVUSUxURVNUMTAeFw0xODA3MTYyMzU5NTZaFw00NTEyMDEyMzU5NTZaMBcxFTAT\n"
        "BgNVBAMMDFBFTVVUSUxURVNUMTB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQDMfDxC\n"
        "DcBTMAjrmo+yNBuYjavI47dPGPrqIXzfAx7L6M2Bg1ZYDaO8xXgc0+7aZZRg7Fe1\n"
        "Gt0EJEourKA6qN0z4gTU5KWZrPLPwPHU75F90jgThdkmHdO7j3lr2MPjsvUCAwEA\n"
        "ATANBgkqhkiG9w0BAQsFAANhAEsa1QiHgPwW0V4VLtRk7xyKIyCo+D0rgQA1qLmW\n"
        "69aMW12GE+sxGo7INDP2bdQGB/udG5V6FnWNTP89VwakKjU4l6LoqtUtncwoGNgT\n"
        "U2aPnxQpNXW7pWdBVSIBhSnptw==\n"
        "-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBXzCB6gIJAMbKbzUVGQTBMA0GCSqGSIb3DQEBCwUAMBcxFTATBgNVBAMMDFBF\n"
        "TVVUSUxURVNUMjAeFw0xODA3MTYyMzU5NDNaFw00NTEyMDEyMzU5NDNaMBcxFTAT\n"
        "BgNVBAMMDFBFTVVUSUxURVNUMjB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQCuUQFO\n"
        "blDXlrJF45Hn86Mb+UAjwnECaaG9Uj7oldNwEwCimhbCQsDYTRzlAFRbdm+S6Lri\n"
        "0KbhKsqDz2V4n3scLnigsLU9pLGGtAF2W/pONUIEBOwsNVL8qGW1oy6A3V0CAwEA\n"
        "ATANBgkqhkiG9w0BAQsFAANhACjrgsP630Mgyj7LDcyV9/tIr+f3ghjyVIyedFQo\n"
        "MJ0if+4o9MKN/7ius4hvI+L6M9aXGyFp/JlRK4p5upqiG6J/vrG3TNPjZMD5wen8\n"
        "/oMJ7lk8yNVYR9zZQgfVzUPlcA==\n"
        "-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBXzCB6gIJANXCDoURTF5MMA0GCSqGSIb3DQEBCwUAMBcxFTATBgNVBAMMDFBF\n"
        "TVVUSUxURVNUMTAeFw0xODA3MTYyMzU5NTZaFw00NTEyMDEyMzU5NTZaMBcxFTAT\n"
        "BgNVBAMMDFBFTVVUSUxURVNUMTB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQDMfDxC\n"
        "DcBTMAjrmo+yNBuYjavI47dPGPrqIXzfAx7L6M2Bg1ZYDaO8xXgc0+7aZZRg7Fe1\n"
        "Gt0EJEourKA6qN0z4gTU5KWZrPLPwPHU75F90jgThdkmHdO7j3lr2MPjsvUCAwEA\n"
        "ATANBgkqhkiG9w0BAQsFAANhAEsa1QiHgPwW0V4VLtRk7xyKIyCo+D0rgQA1qLmW\n"
        "69aMW12GE+sxGo7INDP2bdQGB/udG5V6FnWNTP89VwakKjU4l6LoqtUtncwoGNgT\n"
        "U2aPnxQpNXW7pWdBVSIBhSnptw==\n"
        "-----END CERTIFICATE-----"
    };
    BIO *bio_mems[ITERS];

    for(int i = 0; i < ITERS; ++i) {
        bio_mems[i] = BIO_new_mem_buf((void *) certs[i], -1);
    }

    X509 **x509_auths = NULL;
    for(int i = 0; i < ITERS; ++i) {
        arrput(x509_auths, PEM_read_bio_X509(bio_mems[i], NULL, NULL, NULL));
    }

    spiffeid_TrustDomain td1 = { "example1.com" };
    spiffeid_TrustDomain td2 = { "example2.com" };
    spiffeid_TrustDomain td3 = { "example1.com" };

    x509bundle_Bundle *bundle_ptr1 = x509bundle_New(td1);
    x509bundle_Bundle *bundle_ptr2 = x509bundle_New(td2);
    x509bundle_Bundle *bundle_ptr3 = x509bundle_New(td3);

    ck_assert(x509bundle_Bundle_Equal(bundle_ptr1, bundle_ptr1));
    ck_assert(x509bundle_Bundle_Equal(bundle_ptr2, bundle_ptr2));
    ck_assert(x509bundle_Bundle_Equal(bundle_ptr3, bundle_ptr3));
    ck_assert(!x509bundle_Bundle_Equal(bundle_ptr1, bundle_ptr2));
    ck_assert(x509bundle_Bundle_Equal(bundle_ptr1, bundle_ptr3));
    ck_assert(!x509bundle_Bundle_Equal(bundle_ptr2, bundle_ptr3));

    x509bundle_Bundle_AddX509Authority(bundle_ptr1, x509_auths[0]);
    x509bundle_Bundle_AddX509Authority(bundle_ptr1, x509_auths[1]);
    ck_assert(x509bundle_Bundle_Equal(bundle_ptr1, bundle_ptr1));
    ck_assert(!x509bundle_Bundle_Equal(bundle_ptr1, bundle_ptr2));
    ck_assert(!x509bundle_Bundle_Equal(bundle_ptr1, bundle_ptr3));

    x509bundle_Bundle_AddX509Authority(bundle_ptr3, x509_auths[0]);
    ck_assert(x509bundle_Bundle_Equal(bundle_ptr3, bundle_ptr3));
    ck_assert(!x509bundle_Bundle_Equal(bundle_ptr3, bundle_ptr1));
    ck_assert(!x509bundle_Bundle_Equal(bundle_ptr3, bundle_ptr2));

    x509bundle_Bundle_AddX509Authority(bundle_ptr3, x509_auths[1]);
    ck_assert(x509bundle_Bundle_Equal(bundle_ptr3, bundle_ptr3));
    ck_assert(x509bundle_Bundle_Equal(bundle_ptr3, bundle_ptr1));
    ck_assert(!x509bundle_Bundle_Equal(bundle_ptr3, bundle_ptr2));

    x509bundle_Bundle_AddX509Authority(bundle_ptr2, x509_auths[0]);
    x509bundle_Bundle_AddX509Authority(bundle_ptr2, x509_auths[1]);
    ck_assert(x509bundle_Bundle_Equal(bundle_ptr2, bundle_ptr2));
    ck_assert(!x509bundle_Bundle_Equal(bundle_ptr2, bundle_ptr1));
    ck_assert(!x509bundle_Bundle_Equal(bundle_ptr2, bundle_ptr3));

    for(int i = 0; i < ITERS; ++i) {
        BIO_free(bio_mems[i]);
        X509_free(x509_auths[i]);
    }
    arrfree(x509_auths);
    x509bundle_Bundle_Free(bundle_ptr1);
    x509bundle_Bundle_Free(bundle_ptr2);
    x509bundle_Bundle_Free(bundle_ptr3);
}
END_TEST

START_TEST(test_x509bundle_Bundle_Clone)
{
    spiffeid_TrustDomain td = { "example.com" };
    err_t err;

    x509bundle_Bundle *bundle_ptr1
        = x509bundle_Load(td, "./resources/certs.pem", &err);
    x509bundle_Bundle *bundle_ptr2 = x509bundle_Bundle_Clone(bundle_ptr1);

    ck_assert(x509bundle_Bundle_Equal(bundle_ptr1, bundle_ptr2));

    x509bundle_Bundle_Free(bundle_ptr1);
    x509bundle_Bundle_Free(bundle_ptr2);
}
END_TEST

START_TEST(test_x509bundle_Bundle_GetX509BundleForTrustDomain)
{
    spiffeid_TrustDomain td1 = { "example.com" };
    spiffeid_TrustDomain td2 = { "example2.com" };
    err_t err;

    x509bundle_Bundle *bundle_ptr
        = x509bundle_Load(td1, "./resources/certs.pem", &err);

    x509bundle_Bundle *td_bundle;

    td_bundle
        = x509bundle_Bundle_GetX509BundleForTrustDomain(bundle_ptr, td1, &err);

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert(td_bundle == bundle_ptr);

    td_bundle
        = x509bundle_Bundle_GetX509BundleForTrustDomain(bundle_ptr, td2, &err);

    ck_assert_uint_ne(err, NO_ERROR);
    ck_assert(td_bundle == NULL);

    x509bundle_Bundle_Free(bundle_ptr);
}
END_TEST

Suite *bundle_suite(void)
{
    Suite *s = suite_create("bundle");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_x509bundle_New);
    tcase_add_test(tc_core, test_x509bundle_Parse);
    tcase_add_test(tc_core, test_x509bundle_Load);
    tcase_add_test(tc_core, test_x509bundle_FromX509Authorities);
    tcase_add_test(tc_core, test_x509bundle_Bundle_X509Authorities);
    tcase_add_test(tc_core, test_x509bundle_Bundle_HasX509Authority);
    tcase_add_test(tc_core, test_x509bundle_Bundle_AddX509Authority);
    tcase_add_test(tc_core, test_x509bundle_Bundle_RemoveX509Authority);
    tcase_add_test(tc_core, test_x509bundle_Bundle_SetX509Authorities);
    tcase_add_test(tc_core, test_x509bundle_Bundle_Empty);
    tcase_add_test(tc_core, test_x509bundle_Bundle_Equal);
    tcase_add_test(tc_core, test_x509bundle_Bundle_Clone);
    tcase_add_test(tc_core,
                   test_x509bundle_Bundle_GetX509BundleForTrustDomain);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    Suite *s = bundle_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
