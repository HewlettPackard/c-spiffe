#include "endpoint.h"

#include <openssl/pem.h>
#include <openssl/ssl.h>

// from "spiffeid/src/id.h"
static UriUriA URL_parse(const char *str, err_t *err)
{
    UriUriA uri;
    const char *err_pos;
    if(uriParseSingleUriA(&uri, str, &err_pos) == URI_SUCCESS) {
        *err = NO_ERROR;
    } else {
        *err = ERROR1;
    }

    return uri;
}
// ditto
static string_t URI_to_string(UriUriA *uri)
{
    int len;
    uriToStringCharsRequiredA(uri, &len);

    string_t str_uri = NULL;
    arrsetlen(str_uri, len + 1);

    uriToStringA(str_uri, uri, len + 1, NULL);

    return str_uri;
}

spiffebundle_Endpoint *spiffebundle_Endpoint_New()
{
    spiffebundle_Endpoint *endpoint
        = (spiffebundle_Endpoint *) calloc(1, sizeof(*endpoint));
    endpoint->bundle_source = NULL;
    endpoint->owns_bundle = false;
    endpoint->trust_domain.name = NULL;
    endpoint->url = NULL;
    endpoint->profile = NONE;
    endpoint->curl_handle = NULL;
    return endpoint;
}

void spiffebundle_Endpoint_Free(spiffebundle_Endpoint *endpoint)
{
    if(endpoint) {
        if(endpoint->owns_bundle) {
            spiffebundle_Source_Free(endpoint->bundle_source);
            endpoint->owns_bundle = false;
        }
        if(endpoint->url) {
            util_string_t_Free(endpoint->url);
        }
        if(endpoint->trust_domain.name) {
            spiffeid_TrustDomain_Free(&(endpoint->trust_domain));
        }
        if(!spiffeid_ID_IsZero(endpoint->spiffe_id)) {
            spiffeid_ID_Free(&endpoint->spiffe_id);
        }
        if(endpoint->curl_handle) {
            curl_free(endpoint->curl_handle);
        }
        free(endpoint);
    }
}

err_t spiffebundle_Endpoint_Config_HTTPS_WEB(spiffebundle_Endpoint *endpoint,
                                             const char *url,
                                             spiffeid_TrustDomain trust_domain)
{
    err_t err = NO_ERROR;
    if(!endpoint) {
        return ERROR1; // NULL endpoint pointer
    }
    if(!url) {
        return ERROR2; // empty/NULL url string
    }
    UriUriA temp_uri = URL_parse(url, &err);
    if(err) {
        uriFreeUriMembersA(&temp_uri);
        return ERROR2; // invalid url string
    }
    endpoint->url = URI_to_string(&temp_uri);
    uriFreeUriMembersA(&temp_uri);
    if(!trust_domain.name) {
        return ERROR3; // empty/NULL trust domain name
    }
    endpoint->trust_domain
        = spiffeid_TrustDomainFromString(trust_domain.name, &err);
    if(err) {
        return ERROR3;
    }
    endpoint->profile = HTTPS_WEB;
    endpoint->owns_bundle = false;
    return NO_ERROR;
}

err_t spiffebundle_Endpoint_Config_HTTPS_SPIFFE(
    spiffebundle_Endpoint *endpoint, const char *url,
    spiffeid_TrustDomain trust_domain, string_t spiffe_id,
    spiffebundle_Source *source)
{
    err_t err = NO_ERROR;
    if(!endpoint) {
        return ERROR1; // NULL endpoint pointer
    }
    if(!url) {
        return ERROR2; // empty/NULL url string
    }
    if(!source) {
        return ERROR6; // no source of initial bundle provided
    }
    UriUriA temp_uri = URL_parse(url, &err);
    if(err) {
        uriFreeUriMembersA(&temp_uri);
        return ERROR2; // invalid url string
    }
    if(!trust_domain.name) {
        return ERROR3; // empty/NULL trust domain name
    }
    endpoint->trust_domain
        = spiffeid_TrustDomainFromString(trust_domain.name, &err);
    if(err) {
        return ERROR3;
    }
    endpoint->spiffe_id = spiffeid_FromString(spiffe_id, &err);
    if(err) {
        return ERROR5; // couldn't parse spiffeID
    }
    endpoint->url = URI_to_string(&temp_uri);
    uriFreeUriMembersA(&temp_uri);
    endpoint->bundle_source = source;
    endpoint->profile = HTTPS_SPIFFE;
    endpoint->owns_bundle = false;
    return NO_ERROR;
}

spiffebundle_Bundle *spiffebundle_Endpoint_GetBundleForTrustDomain(
    spiffebundle_Endpoint *endpoint, spiffeid_TrustDomain trust_domain,
    err_t *err)
{
    if(!endpoint) {
        *err = ERROR1;
        return NULL;
    }
    if(!trust_domain.name) {
        *err = ERROR2;
        return NULL;
    }
    if(!endpoint->bundle_source) {
        *err = ERROR3;
        return NULL;
    }
    return spiffebundle_Source_GetSpiffeBundleForTrustDomain(
        endpoint->bundle_source, trust_domain, err);
}

static size_t write_function(void *ptr, size_t size, size_t nmemb,
                             string_t *result)
{
    size_t len = size * nmemb;
    string_t pos = arraddnptr(*result, len);
    memcpy(pos, ptr, len);
    return len;
}

static CURLcode sslctx_function(CURL *curl, void *sslctx, void *parm)
{
    CURLcode rv = CURLE_ABORTED_BY_CALLBACK;

    /** This example uses two (fake) certificates **/

    BIO *cbio = (BIO *) parm;
    // BIO_new_mem_buf(mypem, strlen((mypem)));
    X509_STORE *cts = SSL_CTX_get_cert_store((SSL_CTX *) sslctx);
    int i;
    STACK_OF(X509_INFO) * inf;
    (void) curl;
    //   (void)parm;

    if(!cts || !cbio) {
        return rv;
    }

    inf = PEM_X509_INFO_read_bio(cbio, NULL, NULL, NULL);

    if(!inf) {
        // BIO_free(cbio);
        return rv;
    }

    for(i = 0; i < sk_X509_INFO_num(inf); i++) {
        X509_INFO *itmp = sk_X509_INFO_value(inf, i);
        if(itmp->x509) {
            X509_STORE_add_cert(cts, itmp->x509);
        }
        if(itmp->crl) {
            X509_STORE_add_crl(cts, itmp->crl);
        }
    }

    sk_X509_INFO_pop_free(inf, X509_INFO_free);
    // BIO_free(cbio);

    rv = CURLE_OK;
    return rv;
}

err_t spiffebundle_Endpoint_Fetch(spiffebundle_Endpoint *endpoint)
{
    if(!endpoint) {
        return ERROR1;
    }
    if(!endpoint->trust_domain.name) {
        return ERROR2;
    }
    // if handle exists, reuse.
    CURL *curl
        = endpoint->curl_handle ? endpoint->curl_handle : curl_easy_init();
    if(!curl) {
        return ERROR3;
    }

    CURLcode res;
    string_t response = NULL;
    err_t err = NO_ERROR;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_function);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_URL, endpoint->url);
    curl_easy_setopt(curl, CURLOPT_PORT, 443);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);

    switch(endpoint->profile) {

        int resp_code;
    case HTTPS_WEB:
    {
        res = curl_easy_perform(curl);
        if(res == CURLE_OK) {
            res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &resp_code);
            if(resp_code == 200
               || (resp_code / 100 == 3)) { // 200 OK or 300 redirect

                spiffebundle_Bundle *bundle = spiffebundle_Parse(
                    endpoint->trust_domain, response, &err);
                if(err) {
                    return ERROR5;
                }
                endpoint->bundle_source
                    = spiffebundle_SourceFromBundle(bundle);
                endpoint->owns_bundle = true;
                util_string_t_Free(response);
            } else {
                return ERROR4;
            }
        } else {
            printf("ERROR CODE: %d\n", res);
            return ERROR6;
        }
        break;
    }

    case HTTPS_SPIFFE:
    {
        spiffebundle_Bundle *server_bundle
            = spiffebundle_Endpoint_GetBundleForTrustDomain(
                endpoint, endpoint->trust_domain, &err);
        BIO *cert_bio = BIO_new(BIO_s_mem());
        for(size_t i = 0, size = arrlenu(server_bundle->x509_auths); i < size;
            ++i) {
            PEM_write_bio_X509(cert_bio, server_bundle->x509_auths[i]);
        }

        curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, sslctx_function);
        curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, cert_bio);
        res = curl_easy_perform(curl);

        if(res == CURLE_OK) {
            res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &resp_code);
            if(resp_code == 200
               || (resp_code / 100 == 3)) { // 200 OK or 300 redirect
                spiffebundle_Bundle *bundle = spiffebundle_Parse(
                    endpoint->trust_domain, response, &err);
                if(err) {
                    return ERROR5;
                }
                endpoint->bundle_source
                    = spiffebundle_SourceFromBundle(bundle);
                endpoint->owns_bundle = true;
                util_string_t_Free(response);
            } else {
                return ERROR4;
            }
        } else {
            printf("ERROR CODE: %d\n", res);
            return ERROR6;
        }
        BIO_free(cert_bio);
        break;
    }

    case NONE:
    default:
        return ERROR6; // NOT_IMPLEMENTED
        break;
    }

    curl_easy_cleanup(curl);
    endpoint->curl_handle = NULL;
    return NO_ERROR;
}
