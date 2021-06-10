#include "bundle/x509bundle/src/bundle.h"
#include "internal/x509util/src/util.h"
#include <openssl/pem.h>

x509bundle_Bundle *x509bundle_New(const spiffeid_TrustDomain td)
{
    x509bundle_Bundle *bundleptr = malloc(sizeof *bundleptr);
    if(bundleptr) {
        bundleptr->td.name = string_new(td.name);
        bundleptr->auths = NULL;
        mtx_init(&(bundleptr->mtx), mtx_plain);
    }

    return bundleptr;
}

x509bundle_Bundle *
x509bundle_FromX509Authorities(const spiffeid_TrustDomain td, X509 **auths)
{
    x509bundle_Bundle *bundleptr = malloc(sizeof *bundleptr);
    if(bundleptr) {
        bundleptr->td.name = string_new(td.name);
        bundleptr->auths = x509util_CopyX509Authorities(auths);
        mtx_init(&(bundleptr->mtx), mtx_plain);
    }

    return bundleptr;
}

x509bundle_Bundle *x509bundle_Load(const spiffeid_TrustDomain td,
                                   const char *path, err_t *err)
{
    x509bundle_Bundle *bundleptr = NULL;
    FILE *fx509 = fopen(path, "r");
    if(fx509) {
        string_t buffer = FILE_to_string(fx509);
        fclose(fx509);
        // string end
        // arrput(buffer, (byte) 0);
        bundleptr = x509bundle_Parse(td, buffer, err);
        arrfree(buffer);
    } else {
        // could not open file
        *err = ERROR1;
    }

    return bundleptr;
}

x509bundle_Bundle *x509bundle_Parse(const spiffeid_TrustDomain td,
                                    const char *bundle_bytes, err_t *err)
{
    x509bundle_Bundle *bundle = x509bundle_New(td);

    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, bundle_bytes);

    *err = NO_ERROR;

    while(true) {
        X509 *cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
        if(cert) {
            arrput(bundle->auths, cert);
        } else
            break;
    }

    BIO_free(bio_mem);
    return bundle;
}

spiffeid_TrustDomain x509bundle_Bundle_TrustDomain(const x509bundle_Bundle *b)
{
    return b->td;
}

X509 **x509bundle_Bundle_X509Authorities(x509bundle_Bundle *b)
{
    mtx_lock(&(b->mtx));
    X509 **copy_auths = x509util_CopyX509Authorities((X509 **) b->auths);
    mtx_unlock(&(b->mtx));

    return copy_auths;
}

void x509bundle_Bundle_AddX509Authority(x509bundle_Bundle *b, X509 *auth)
{
    mtx_lock(&(b->mtx));
    bool suc = false;
    // searches for certificate
    for(size_t i = 0, size = arrlenu(b->auths); i < size; ++i) {
        if(!X509_cmp(b->auths[i], auth)) {
            // b->auths[i] == auth
            suc = true;
            break;
        }
    }
    if(!suc) {
        X509_up_ref(auth);
        arrput(b->auths, auth);
    }
    mtx_unlock(&(b->mtx));
}

void x509bundle_Bundle_RemoveX509Authority(x509bundle_Bundle *b, X509 *auth)
{
    mtx_lock(&(b->mtx));
    for(size_t i = 0, size = arrlenu(b->auths); i < size; ++i) {
        if(!X509_cmp(b->auths[i], auth)) {
            X509_free(b->auths[i]);
            arrdel(b->auths, i);
            break;
        }
    }
    mtx_unlock(&(b->mtx));
}

bool x509bundle_Bundle_HasX509Authority(x509bundle_Bundle *b, X509 *auth)
{
    mtx_lock(&(b->mtx));
    bool present = false;
    for(size_t i = 0, size = arrlenu(b->auths); i < size; ++i) {
        if(!X509_cmp(b->auths[i], auth)) {
            present = true;
            break;
        }
    }
    mtx_unlock(&(b->mtx));

    return present;
}

void x509bundle_Bundle_SetX509Authorities(x509bundle_Bundle *b, X509 **auths)
{
    mtx_lock(&(b->mtx));
    for(size_t i = 0, size = arrlenu(b->auths); i < size; ++i) {
        X509_free(b->auths[i]);
    }
    arrfree(b->auths);
    b->auths = x509util_CopyX509Authorities(auths);
    mtx_unlock(&(b->mtx));
}

bool x509bundle_Bundle_Empty(x509bundle_Bundle *b)
{
    mtx_lock(&(b->mtx));
    bool empty = (arrlenu(b->auths) == 0);
    mtx_unlock(&(b->mtx));

    return empty;
}

bool x509bundle_Bundle_Equal(const x509bundle_Bundle *b1,
                             const x509bundle_Bundle *b2)
{
    if(b1 && b2) {
        // equal trust domains and equal X509 authorities
        return !strcmp(b1->td.name, b2->td.name)
               && x509util_CertsEqual((X509 **) b1->auths,
                                      (X509 **) b2->auths);
    } else
        return b1 == b2;
}

x509bundle_Bundle *x509bundle_Bundle_Clone(x509bundle_Bundle *b)
{
    mtx_lock(&(b->mtx));
    x509bundle_Bundle *bundle
        = x509bundle_FromX509Authorities(b->td, (X509 **) b->auths);
    mtx_unlock(&(b->mtx));

    return bundle;
}

x509bundle_Bundle *x509bundle_Bundle_GetX509BundleForTrustDomain(
    x509bundle_Bundle *b, const spiffeid_TrustDomain td, err_t *err)
{
    mtx_lock(&(b->mtx));
    x509bundle_Bundle *bundle = NULL;
    // different trust domains error
    *err = ERROR1;
    // if the TDs are equal
    if(!strcmp(b->td.name, td.name)) {
        bundle = b;
        *err = NO_ERROR;
    }
    mtx_unlock(&(b->mtx));
    return bundle;
}

void x509bundle_Bundle_Free(x509bundle_Bundle *b)
{
    if(b) {
        // mtx_destroy(&(b->mtx));
        for(size_t i = 0, size = arrlenu(b->auths); i < size; ++i) {
            X509_free(b->auths[i]);
        }
        arrfree(b->auths);
        spiffeid_TrustDomain_Free(&(b->td));
        free(b);
    }
}
