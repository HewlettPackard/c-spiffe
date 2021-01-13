#include <openssl/pem.h>
#include <check.h>
#include "../src/util.h"

#define STB_DS_IMPLEMENTATION
#include "../../../utils/src/stb_ds.h"

START_TEST(test_x509util_CopyX509Authorities)
{
    const int ITERS = 4;

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
        "MIIB/DCCAWWgAwIBAgIBADANBgkqhkiG9w0BAQsFADCBmzELMAkGA1UEBhMCSlAx\n"
        "DjAMBgNVBAgTBVRva3lvMRAwDgYDVQQHEwdDaHVvLWt1MREwDwYDVQQKEwhGcmFu\n"
        "azRERDEYMBYGA1UECxMPV2ViQ2VydCBTdXBwb3J0MRgwFgYDVQQDEw9GcmFuazRE\n"
        "RCBXZWIgQ0ExIzAhBgkqhkiG9w0BCQEWFHN1cHBvcnRAZnJhbms0ZGQuY29tMAQX\n"
        "ABcAMEoxCzAJBgNVBAYTAkpQMQ4wDAYDVQQIDAVUb2t5bzERMA8GA1UECgwIRnJh\n"
        "bms0REQxGDAWBgNVBAMMD3d3dy5leGFtcGxlLmNvbTBcMA0GCSqGSIb3DQEBAQUA\n"
        "A0sAMEgCQQCb/GaQeYRCu6sT/St7+N4VEuXxk+MGinu4seGeJruVAb/nMO1khQLd\n"
        "FWmoNLAG7D81PB4bK4/6jwAb3wfGrFMHAgMBAAEwDQYJKoZIhvcNAQELBQADgYEA\n"
        "ZH/vPnCRgpVT06qXJthl/+kch+dfkf0g1/UJHgzigJNTQIwq4NX20mNBBHaR+E/6\n"
        "gvmDWPuHXw9xOcpnXEEIwYCdg3Cy4TjKsh0s4phSTvqrdPKlLx/io0JAauwxhZg2\n"
        "OYWt4ulA5/7XXO+GSMiifuQObzTEmeYn7+8rAY2978Y=\n"
        "-----END CERTIFICATE-----",
        "-----BEGIN CERTIFICATE-----\n"
        "MIIHIDCCBgigAwIBAgIIMrM8cLO76sYwDQYJKoZIhvcNAQEFBQAwSTELMAkGA1UE\n"
        "BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl\n"
        "iftrJvzAOMAPY5b/klZvqH6Ddubg/hUVPkiv4mr5MfWfglCQdFF1EBGNoZSFAU7y\n"
        "ZkGENAvDmv+5xVCZELeiWA2PoNV4m/SW6NHrF7gz4MwQssqP9dGMbKPOF/D2nxic\n"
        "TnD5WkGMCWpLgqDWWRoOrt6xf0BPWukQBDMHULlZgXzNtoGlEnwztLlnf0I/WWIS\n"
        "eBSyDTeFJfopvoqXuws23X486fdKcCAV1n/Nl6y2z+uVvcyTRxY2/jegmV0n0kHf\n"
        "gfcKzw==\n"
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

    BIO *bio_mems[] = {
        BIO_new_mem_buf((void*) buff[0], -1),
        BIO_new_mem_buf((void*) buff[1], -1),
        BIO_new_mem_buf((void*) buff[2], -1),
        BIO_new_mem_buf((void*) buff[3], -1)
    };

    X509 **certs = NULL;
    for(int i = 0; i < ITERS; ++i)
    {
        //load certificate here
        //dummy
        X509 *cert = PEM_read_bio_X509(bio_mems[i], NULL, NULL, NULL);
        if(cert)
            arrput(certs, cert);
    }

    X509 **certs_copy = x509util_CopyX509Authorities(certs);

    ck_assert_uint_eq(arrlenu(certs), arrlenu(certs_copy));
    for(size_t i = 0, size = arrlenu(certs); i < size; ++i)
    {
        ck_assert_int_eq(X509_cmp(certs[i], certs_copy[i]), 0);

        X509_free(certs[i]);
        X509_free(certs_copy[i]);
    }

    arrfree(certs);
    arrfree(certs_copy);
}
END_TEST

START_TEST(test_x509util_CertsEqual)
{
    const int ITERS = 4;

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
        "MIIB/DCCAWWgAwIBAgIBADANBgkqhkiG9w0BAQsFADCBmzELMAkGA1UEBhMCSlAx\n"
        "DjAMBgNVBAgTBVRva3lvMRAwDgYDVQQHEwdDaHVvLWt1MREwDwYDVQQKEwhGcmFu\n"
        "azRERDEYMBYGA1UECxMPV2ViQ2VydCBTdXBwb3J0MRgwFgYDVQQDEw9GcmFuazRE\n"
        "RCBXZWIgQ0ExIzAhBgkqhkiG9w0BCQEWFHN1cHBvcnRAZnJhbms0ZGQuY29tMAQX\n"
        "ABcAMEoxCzAJBgNVBAYTAkpQMQ4wDAYDVQQIDAVUb2t5bzERMA8GA1UECgwIRnJh\n"
        "bms0REQxGDAWBgNVBAMMD3d3dy5leGFtcGxlLmNvbTBcMA0GCSqGSIb3DQEBAQUA\n"
        "A0sAMEgCQQCb/GaQeYRCu6sT/St7+N4VEuXxk+MGinu4seGeJruVAb/nMO1khQLd\n"
        "FWmoNLAG7D81PB4bK4/6jwAb3wfGrFMHAgMBAAEwDQYJKoZIhvcNAQELBQADgYEA\n"
        "ZH/vPnCRgpVT06qXJthl/+kch+dfkf0g1/UJHgzigJNTQIwq4NX20mNBBHaR+E/6\n"
        "gvmDWPuHXw9xOcpnXEEIwYCdg3Cy4TjKsh0s4phSTvqrdPKlLx/io0JAauwxhZg2\n"
        "OYWt4ulA5/7XXO+GSMiifuQObzTEmeYn7+8rAY2978Y=\n"
        "-----END CERTIFICATE-----",
        "-----BEGIN CERTIFICATE-----\n"
        "MIIHIDCCBgigAwIBAgIIMrM8cLO76sYwDQYJKoZIhvcNAQEFBQAwSTELMAkGA1UE\n"
        "BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl\n"
        "iftrJvzAOMAPY5b/klZvqH6Ddubg/hUVPkiv4mr5MfWfglCQdFF1EBGNoZSFAU7y\n"
        "ZkGENAvDmv+5xVCZELeiWA2PoNV4m/SW6NHrF7gz4MwQssqP9dGMbKPOF/D2nxic\n"
        "TnD5WkGMCWpLgqDWWRoOrt6xf0BPWukQBDMHULlZgXzNtoGlEnwztLlnf0I/WWIS\n"
        "eBSyDTeFJfopvoqXuws23X486fdKcCAV1n/Nl6y2z+uVvcyTRxY2/jegmV0n0kHf\n"
        "gfcKzw==\n"
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

    BIO *bio_mems[] = {
        BIO_new_mem_buf((void*) buff[0], -1),
        BIO_new_mem_buf((void*) buff[1], -1),
        BIO_new_mem_buf((void*) buff[2], -1),
        BIO_new_mem_buf((void*) buff[3], -1)
    };

    X509 **certs1 = NULL, **certs2 = NULL;

    for(int i = 0; i < ITERS; ++i)
    {
        //load certificate here
        //dummy
        X509 *cert = PEM_read_bio_X509(bio_mems[i], NULL, NULL, NULL);

        arrput(certs1, cert);
        arrput(certs2, cert);
    }

    ck_assert(x509util_CertsEqual(certs1, certs2));
    
    arrpop(certs1);
    ck_assert(!x509util_CertsEqual(certs1, certs2));

    arrpop(certs2);
    ck_assert(x509util_CertsEqual(certs1, certs2));
    
    arrdel(certs1, 0);
    ck_assert(!x509util_CertsEqual(certs1, certs2));

    X509 *temp_cert = arrpop(certs1);
    arrins(certs1, 0, temp_cert);
    arrdelswap(certs2, 0);
    ck_assert(x509util_CertsEqual(certs1, certs2));

    arrfree(certs1);
    arrfree(certs2);
    ck_assert(x509util_CertsEqual(certs1, certs2));
}
END_TEST

Suite* util_suite(void)
{
    Suite *s = suite_create("util");
    TCase *tc_core = tcase_create("core");

    suite_add_tcase(s, tc_core);

    tcase_add_test(tc_core, test_x509util_CopyX509Authorities);
    tcase_add_test(tc_core, test_x509util_CertsEqual);

    return s;
}

int main(void)
{
    Suite *s = util_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);
    
    srunner_free(sr);
    
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}