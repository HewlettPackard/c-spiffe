#include "c-spiffe/spiffetls/tlsconfig/config.h"
#include "c-spiffe/workload/jwtsource.h"
#include "c-spiffe/workload/x509source.h"

#include <curl/curl.h>

static size_t write_function(void *ptr, size_t size, size_t nmemb,
                             void *userdata)
{
    const size_t len = size * nmemb;
    string_t *str = (string_t *) userdata;
    arrsetlen(*str, len);
    memcpy(*str, ptr, len);
    // end of string
    arrpush(*str, 0);

    return len;
}

int main(int argc, char **argv)
{
    err_t err;
    workloadapi_X509Source *x509source = workloadapi_NewX509Source(NULL, &err);
    if(err != NO_ERROR) {
        printf("workloadapi_NewX509Source() failed: error %u\n", err);
        exit(-1);
    }
    err = workloadapi_X509Source_Start(x509source);
    if(err != NO_ERROR) {
        printf("workloadapi_X509Source_Start() failed: error %u\n", err);
        exit(-1);
    }

    workloadapi_JWTSource *jwtsource = workloadapi_NewJWTSource(NULL, &err);
    if(err != NO_ERROR) {
        printf("workloadapi_NewJWTSource() failed: error %u\n", err);
        exit(-1);
    }
    err = workloadapi_JWTSource_Start(jwtsource);
    if(err != NO_ERROR) {
        printf("workloadapi_JWTSource_Start() failed: error %u\n", err);
        exit(-1);
    }

    jwtsvid_Params params
        = { .audience = string_new("spiffe://example.com/server"),
            .extra_audiences = NULL,
            .subject = NULL };
    jwtsvid_SVID *jwtsvid
        = workloadapi_JWTSource_GetJWTSVID(jwtsource, &params, &err);
    arrfree(params.audience);
    if(!jwtsvid || err != NO_ERROR) {
        printf("workloadapi_JWTSource_GetJWTSVID() failed: error %u\n", err);
        exit(-1);
    }

    string_t header_arg = string_new("Authorization: Bearer ");
    header_arg = string_push(header_arg, jwtsvid_SVID_Marshal(jwtsvid));
    struct curl_slist *list = curl_slist_append(NULL, header_arg);
    arrfree(header_arg);
    string_t response = NULL;

    x509svid_SVID *x509svid
        = workloadapi_X509Source_GetX509SVID(x509source, &err);
    if(!x509svid || err != NO_ERROR) {
        printf("workloadapi_X509Source_GetX509SVID() failed: error %u\n", err);
        exit(-1);
    }
    x509bundle_Bundle *x509bundle
        = workloadapi_X509Source_GetX509BundleForTrustDomain(
            x509source, x509svid->id.td, &err);
    if(!x509svid || err != NO_ERROR) {
        printf("workloadapi_X509Source_GetX509BundleForTrustDomain() failed: "
               "error %u\n",
               err);
        exit(-1);
    }

    // leaf certificate
    string_t cert_filename = string_new(tmpnam(NULL));
    FILE *f = fopen(cert_filename, "w");
    // leaf certificate to file
    PEM_write_X509(f, x509svid->certs[0]);
    fclose(f);

    // certificate chain
    string_t ca_filename = string_new(tmpnam(NULL));
    f = fopen(ca_filename, "w");
    // intermediate certificates to file
    for(size_t i = 0, size = arrlenu(x509bundle->auths); i < size; ++i) {
        PEM_write_X509(f, x509bundle->auths[i]);
    }
    fclose(f);

    // certificate private key
    string_t key_filename = string_new(tmpnam(NULL));
    f = fopen(key_filename, "w");
    // leaf private key to file
    PEM_write_PrivateKey(f, x509svid->private_key, NULL, NULL, 0, NULL, NULL);
    fclose(f);

    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, "https://localhost");
    curl_easy_setopt(curl, CURLOPT_PORT, 8443);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_function);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_SSLCERT, cert_filename);
    curl_easy_setopt(curl, CURLOPT_SSLKEY, key_filename);
    curl_easy_setopt(curl, CURLOPT_CAINFO, ca_filename);

    CURLcode res = curl_easy_perform(curl);

    if(res != CURLE_OK) {
        printf("res: %d\n", res);
        printf("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    }

    printf("%s\n", response);

    curl_easy_cleanup(curl);
    curl_slist_free_all(list);
    arrfree(response);

    remove(cert_filename);
    remove(key_filename);
    remove(ca_filename);
    arrfree(cert_filename);
    arrfree(key_filename);
    arrfree(ca_filename);
    workloadapi_X509Source_Free(x509source);
    workloadapi_JWTSource_Free(jwtsource);

    return 0;
}
