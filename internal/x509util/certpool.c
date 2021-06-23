#include "c-spiffe/internal/x509util/certpool.h"
#include <openssl/bio.h>
#include <openssl/x509v3.h>

x509util_CertPool *x509util_CertPool_New(void)
{
    x509util_CertPool *certpool = malloc(sizeof *certpool);
    memset(certpool, 0, sizeof *certpool);

    return certpool;
}

static string_t ASN1_STRING_to_string(const ASN1_STRING *asn1_str)
{
    if(asn1_str) {
        string_t str = string_new_range((const char *) asn1_str->data,
                                        (const char *) asn1_str->data
                                            + asn1_str->length);

        return str;
    }

    return NULL;
}

static string_t X509_NAME_to_string(X509_NAME *name)
{
    if(name) {
        BIO *bio_out = BIO_new(BIO_s_mem());
        X509_NAME_print(bio_out, name, 0);
        BUF_MEM *bio_buf;
        BIO_get_mem_ptr(bio_out, &bio_buf);
        string_t str
            = string_new_range(bio_buf->data, bio_buf->data + bio_buf->length);
        BIO_free(bio_out);

        return str;
    }

    return NULL;
}

void x509util_CertPool_AddCert(x509util_CertPool *certpool, X509 *cert)
{
    if(certpool) {
        if(!x509util_CertPool_contains(certpool, cert)) {
            const size_t n = arrlenu(certpool->certs);
            X509_up_ref(cert);
            arrput(certpool->certs, cert);

            const ASN1_OCTET_STRING *subj_keyid
                = X509_get0_subject_key_id(cert);

            // if extension is supported
            if(subj_keyid) {
                string_t subj_keyid_str = ASN1_STRING_to_string(subj_keyid);

                const int idx
                    = shgeti(certpool->subj_keyid_idcs, subj_keyid_str);
                if(idx >= 0) {
                    // if key id exists, append
                    arrput(certpool->subj_keyid_idcs[idx].value, n);
                } else {
                    // if not, create array and put on the hash
                    int *arr = NULL;
                    arrput(arr, n);
                    shput(certpool->subj_keyid_idcs, subj_keyid_str, arr);
                }

                arrfree(subj_keyid_str);
            }

            string_t name_str
                = X509_NAME_to_string(X509_get_subject_name(cert));
            const int idx = shgeti(certpool->name_idcs, name_str);
            if(idx >= 0) {
                // if name exists, append
                arrput(certpool->name_idcs[idx].value, n);
                arrfree(name_str);
            } else {
                // if not, create array and put on the hash
                int *arr = NULL;
                arrput(arr, n);
                shput(certpool->name_idcs, name_str, arr);
            }
        }
    }
}

bool x509util_CertPool_contains(x509util_CertPool *certpool, X509 *cert)
{
    if(certpool) {
        string_t name_str = X509_NAME_to_string(X509_get_subject_name(cert));

        if(name_str) {
            const int idx = shgeti(certpool->name_idcs, name_str);

            if(idx >= 0) {
                // get certificates with same name
                const int *candidates = certpool->name_idcs[idx].value;

                for(size_t i = 0, size = arrlenu(candidates); i < size; ++i) {
                    const int c = candidates[i];
                    if(!X509_cmp(cert, certpool->certs[c])) {
                        // if one of them is equal, return true
                        arrfree(name_str);
                        return true;
                    }
                }
            }

            arrfree(name_str);
        }
    }

    return false;
}

void x509util_CertPool_Free(x509util_CertPool *certpool)
{
    if(certpool) {
        for(size_t i = 0, size = shlenu(certpool->name_idcs); i < size; ++i) {
            arrfree(certpool->name_idcs[i].value);
        }
        shfree(certpool->name_idcs);

        for(size_t i = 0, size = shlenu(certpool->subj_keyid_idcs); i < size;
            ++i) {
            arrfree(certpool->subj_keyid_idcs[i].value);
        }
        shfree(certpool->subj_keyid_idcs);

        for(size_t i = 0, size = arrlenu(certpool->certs); i < size; ++i) {
            X509_free(certpool->certs[i]);
        }
        arrfree(certpool->certs);

        free(certpool);
    }
}
