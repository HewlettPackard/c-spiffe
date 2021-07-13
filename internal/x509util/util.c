#include "c-spiffe/internal/x509util/util.h"
#include <openssl/x509.h>

X509 **x509util_ParseCertificates(const byte *bytes, const size_t len,
                                  err_t *err)
{
    *err = ERR_DEFAULT;
    BIO *bio_mem = BIO_new(BIO_s_mem());

    if(BIO_write(bio_mem, bytes, len) > 0) {
        X509 **certs = NULL;
        while(true) {
            X509 *cert = d2i_X509_bio(bio_mem, NULL);
            if(cert) {
                arrput(certs, cert);
            } else {
                break;
            }
        }

        if(arrlenu(certs) > 0)
            *err = NO_ERROR;

        return certs;
    }

    return NULL;
}

EVP_PKEY *x509util_ParsePrivateKey(const byte *bytes, const size_t len,
                                   err_t *err)
{
    *err = ERR_DEFAULT;
    BIO *bio_mem = BIO_new(BIO_s_mem());

    if(BIO_write(bio_mem, bytes, len) > 0) {
        EVP_PKEY *pkey = d2i_PrivateKey_bio(bio_mem, NULL);

        if(pkey)
            *err = NO_ERROR;

        return pkey;
    }

    return NULL;
}

X509 **x509util_CopyX509Authorities(X509 **certs)
{
    if(certs) {
        X509 **new_certs = NULL;
        for(size_t i = 0, size = arrlenu(certs); i < size; ++i) {
            X509 *cert = certs[i];
            // ups the ref count, so it is memory safe
            // no need to copy the contents, for now
            if(cert)
                X509_up_ref(cert);
            arrput(new_certs, cert);
        }

        return new_certs;
    }
    return NULL;
}

bool x509util_CertsEqual(X509 **certs1, X509 **certs2)
{
    if(certs1 && certs2) {
        if(arrlenu(certs1) == arrlenu(certs2)) {
            for(size_t i = 0, size = arrlenu(i); i < size; ++i) {
                if(X509_cmp(certs1[i], certs2[i]))
                    return false;
            }

            return true;
        } else
            return false;
    }

    return certs1 == certs2;
}

x509util_CertPool *x509util_NewCertPool(X509 **certs)
{
    x509util_CertPool *certpool = x509util_CertPool_New();

    for(size_t i = 0, size = arrlenu(certs); i < size; ++i) {
        x509util_CertPool_AddCert(certpool, certs[i]);
    }

    return certpool;
}
