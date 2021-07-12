#include "c-spiffe/federation/endpoint.h"
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <uriparser/Uri.h>

// from "spiffeid/id.h"
static UriUriA URL_parse(const char *str, err_t *err)
{
    UriUriA uri;
    const char *err_pos;
    if(uriParseSingleUriA(&uri, str, &err_pos) == URI_SUCCESS) {
        *err = NO_ERROR;
    } else {
        *err = ERR_PARSING;
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
    mtx_init(&endpoint->mutex, mtx_plain);
    return endpoint;
}

void spiffebundle_Endpoint_Free(spiffebundle_Endpoint *endpoint)
{
    if(endpoint) {
        mtx_lock(&endpoint->mutex);
        if(endpoint->owns_bundle) {
            spiffebundle_Source_Free(endpoint->source);
            endpoint->owns_bundle = false;
        }
        if(endpoint->curl_handle) {
            curl_easy_cleanup(endpoint->curl_handle);
            endpoint->curl_handle = NULL;
        }
        mtx_unlock(&endpoint->mutex);
        mtx_destroy(&endpoint->mutex);
        free(endpoint);
    }
}

err_t spiffebundle_Endpoint_ConfigHTTPSWEB(spiffebundle_Endpoint *endpoint,
                                           const char *url,
                                           spiffeid_TrustDomain trust_domain)
{
    err_t err = NO_ERROR;
    if(!endpoint) {
        return ERR_NULL; // NULL endpoint pointer
    }
    if(!url) {
        return ERR_EMPTY_DATA; // empty/NULL url string
    }
    UriUriA temp_uri = URL_parse(url, &err);
    if(err) {
        uriFreeUriMembersA(&temp_uri);
        return ERR_PARSING; // invalid url string
    }
    if(!trust_domain.name) {
        return ERR_INVALID_TRUSTDOMAIN; // empty/NULL trust domain name
    }
    mtx_lock(&endpoint->mutex);
    endpoint->url = URI_to_string(&temp_uri);
    uriFreeUriMembersA(&temp_uri);
    endpoint->td = spiffeid_TrustDomainFromString(trust_domain.name, &err);
    if(err) {

        mtx_unlock(&endpoint->mutex);
        return ERR_INVALID_TRUSTDOMAIN;
    }
    endpoint->profile = HTTPS_WEB;
    endpoint->owns_bundle = false;
    mtx_unlock(&endpoint->mutex);
    return NO_ERROR;
}

err_t spiffebundle_Endpoint_ConfigHTTPSSPIFFE(
    spiffebundle_Endpoint *endpoint, const char *url,
    spiffeid_TrustDomain trust_domain, const char *spiffe_id,
    spiffebundle_Source *source)
{
    err_t err = NO_ERROR;
    if(!endpoint) {
        return ERR_NULL; // NULL endpoint pointer
    }
    if(!url) {
        return ERR_EMPTY_DATA; // empty/NULL url string
    }
    if(!source) {
        return ERR_INVALID_DATA; // no source of initial bundle provided
    }
    if(!trust_domain.name) {
        return ERR_INVALID_TRUSTDOMAIN; // empty/NULL trust domain name
    }
    UriUriA temp_uri = URL_parse(url, &err);
    if(err) {
        uriFreeUriMembersA(&temp_uri);
        return ERR_INVALID_DATA; // invalid url string
    }

    mtx_lock(&endpoint->mutex);
    endpoint->td = spiffeid_TrustDomainFromString(trust_domain.name, &err);
    if(err) {
        mtx_unlock(&endpoint->mutex);
        return ERR_INVALID_TRUSTDOMAIN;
    }
    endpoint->id = spiffeid_FromString(spiffe_id, &err);
    if(err) {
        mtx_unlock(&endpoint->mutex);
        return ERR_PARSING; // couldn't parse spiffeID
    }
    endpoint->url = URI_to_string(&temp_uri);
    uriFreeUriMembersA(&temp_uri);
    endpoint->source = source;
    endpoint->profile = HTTPS_SPIFFE;
    endpoint->owns_bundle = false;
    mtx_unlock(&endpoint->mutex);
    return NO_ERROR;
}

spiffebundle_Bundle *spiffebundle_Endpoint_GetBundleForTrustDomain(
    spiffebundle_Endpoint *endpoint, const spiffeid_TrustDomain trust_domain,
    err_t *err)
{
    if(!endpoint) {
        *err = ERR_NULL;
        return NULL;
    }
    if(!trust_domain.name) {
        *err = ERR_TRUSTDOMAIN_NOTAVAILABLE;
        return NULL;
    }
    mtx_lock(&endpoint->mutex);
    if(!endpoint->source) {
        *err = ERR_NULL;
        mtx_unlock(&endpoint->mutex);
        return NULL;
    }

    spiffebundle_Bundle *ret
        = spiffebundle_Source_GetSpiffeBundleForTrustDomain(endpoint->source,
                                                            trust_domain, err);
    mtx_unlock(&endpoint->mutex);
    return ret;
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
        return ERR_NULL;
    }
    if(!endpoint->td.name) {
        return ERR_INVALID_DATA;
    }
    // if handle exists, reuse.
    mtx_lock(&endpoint->mutex);
    CURL *curl
        = endpoint->curl_handle ? endpoint->curl_handle : curl_easy_init();
    if(!curl) {
        mtx_unlock(&endpoint->mutex);
        return ERR_NULL;
    }
    endpoint->curl_handle = curl;
    mtx_unlock(&endpoint->mutex);

    CURLcode res;
    string_t response = NULL;
    err_t err = NO_ERROR;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_function);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_URL, endpoint->url);
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
                mtx_lock(&endpoint->mutex);
                spiffebundle_Bundle *bundle
                    = spiffebundle_Parse(endpoint->td, response, &err);
                if(err) {
                    mtx_unlock(&endpoint->mutex);
                    return ERR_UNKNOWN_TYPE;
                }
                endpoint->source = spiffebundle_SourceFromBundle(bundle);
                endpoint->owns_bundle = true;
                mtx_unlock(&endpoint->mutex);

                util_string_t_Free(response);
            } else {
                return ERR_UNKNOWN_TYPE;
            }
        } else {
            printf("ERROR CODE: %d\n", res);
            return ERR_GET;
        }
        break;
    }

    case HTTPS_SPIFFE:
    {
        spiffebundle_Bundle *server_bundle
            = spiffebundle_Endpoint_GetBundleForTrustDomain(
                endpoint, endpoint->td, &err);
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
                spiffebundle_Bundle *bundle
                    = spiffebundle_Parse(endpoint->td, response, &err);
                if(err) {
                    return ERR_UNKNOWN_TYPE;
                }
                mtx_lock(&endpoint->mutex);
                endpoint->source = spiffebundle_SourceFromBundle(bundle);
                endpoint->owns_bundle = true;
                mtx_unlock(&endpoint->mutex);
                util_string_t_Free(response);
            } else {
                return ERR_UNKNOWN_TYPE;
            }
        } else {
            printf("ERROR CODE: %d\n", res);
            return ERR_GET;
        }
        BIO_free(cert_bio);
        break;
    }

    case NONE:
    default:
        return ERR_DEFAULT; // NOT_IMPLEMENTED
        break;
    }
    return NO_ERROR;
}

err_t spiffebundle_Endpoint_Cancel(spiffebundle_Endpoint *endpoint)
{
    if(!endpoint) {
        return ERR_NULL;
    }
    mtx_lock(&(endpoint->mutex));
    if(!endpoint->curl_handle) {
        mtx_unlock(&(endpoint->mutex));
        return NO_ERROR;
    }
    curl_easy_cleanup(endpoint->curl_handle);
    endpoint->curl_handle = NULL;
    mtx_unlock(&(endpoint->mutex));
    return NO_ERROR;
}
