#include "spiffetls/tlsconfig/config.h"
#include "workload/jwtsource.h"
#include "workload/x509source.h"

#include <curl/curl.h>

/**
 * TODO:
 * - set x509 certificates in curl
 */

static size_t write_function(void *ptr, size_t size, size_t nmemb,
                             void *userdata)
{
    const size_t len = size * nmemb;
    string_t *str = (string_t *) userdata;
    string_t pos = arraddnptr(*str, len);
    memcpy(pos, ptr, len);
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

    /// TODO: set audience with argv, if possible
    /// TODO: change audience type from string_t to char*
    jwtsvid_Params params
        = { .audience = string_new("spiffe:example.com/server"),
            .extra_audiences = NULL,
            .subject = NULL };
    jwtsvid_SVID *svid
        = workloadapi_JWTSource_GetJWTSVID(jwtsource, &params, &err);
    arrfree(params.audience);
    if(!svid || err != NO_ERROR) {
        printf("workloadapi_JWTSource_GetJETSVID() failed: error %u\n", err);
        exit(-1);
    }

    string_t header_arg = string_new("Authorization: Bearer ");
    header_arg = string_push(header_arg, jwtsvid_SVID_Marshal(svid));
    struct curl_slist *list = curl_slist_append(list, header_arg);
    arrfree(header_arg);
    string_t response = NULL;

    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, "https://localhost");
    curl_easy_setopt(curl, CURLOPT_PORT, 8443);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_function);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);

    if(res != CURLE_OK) {
        printf("curl_easy_perfoem() failed: %s\n", curl_easy_strerror(res));
        exit(-1);
    }

    printf("%s\n", response);

    curl_easy_cleanup(curl);
    curl_slist_free_all(list);
    arrfree(response);

    workloadapi_X509Source_Free(x509source);
    workloadapi_JWTSource_Free(jwtsource);
    jwtsvid_SVID_Free(svid);

    return 0;
}
