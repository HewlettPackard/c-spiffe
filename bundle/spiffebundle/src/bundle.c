#include "bundle/spiffebundle/src/bundle.h"
#include "internal/jwtutil/src/util.h"
#include "internal/x509util/src/util.h"

spiffebundle_Bundle *spiffebundle_New(const spiffeid_TrustDomain td)
{
    spiffebundle_Bundle *bundle = malloc(sizeof *bundle);
    if(bundle) {
        bundle->td.name = string_new(td.name);
        mtx_init(&(bundle->mtx), mtx_plain);
        bundle->jwtAuths = NULL;
        sh_new_strdup(bundle->jwtAuths);
        bundle->x509Auths = NULL;
        bundle->refreshHint = NULL;
        bundle->seqNumber = NULL;
    }
    return bundle;
}

spiffebundle_Bundle *spiffebundle_Load(const spiffeid_TrustDomain td,
                                       const char *path, err_t *err)
{
    spiffebundle_Bundle *bundleptr = NULL;
    FILE *fsb = fopen(path, "r");
    if(fsb) {
        string_t buffer = FILE_to_string(fsb);
        fclose(fsb);
        // string end
        // arrput(buffer, (byte) 0);
        bundleptr = spiffebundle_Parse(td, (const byte *) buffer, err);
        arrfree(buffer);
    } else
        *err = ERROR1;

    return bundleptr;
}

spiffebundle_Bundle *spiffebundle_Parse(const spiffeid_TrustDomain td,
                                        const byte *bundleBytes, err_t *err)
{
    // dummy
    *err = ERROR1;
    if(td.name && bundleBytes) {
        *err = NO_ERROR;
    }

    return NULL;
}

spiffebundle_Bundle *spiffebundle_FromX509Bundle(x509bundle_Bundle *x509bundle)
{
    spiffebundle_Bundle *mbundle
        = spiffebundle_New(x509bundle_Bundle_TrustDomain(x509bundle));

    if(mbundle) {
        mbundle->x509Auths = x509bundle_Bundle_X509Authorities(x509bundle);
    }

    return mbundle;
}

spiffebundle_Bundle *spiffebundle_FromJWTBundle(jwtbundle_Bundle *jwtbundle)
{
    spiffebundle_Bundle *mbundle
        = spiffebundle_New(jwtbundle_Bundle_TrustDomain(jwtbundle));

    if(mbundle) {
        mbundle->jwtAuths = jwtbundle_Bundle_JWTAuthorities(jwtbundle);
    }

    return mbundle;
}

spiffebundle_Bundle *
spiffebundle_FromX509Authorities(const spiffeid_TrustDomain td, X509 **auths)
{
    spiffebundle_Bundle *bundle = spiffebundle_New(td);

    if(bundle) {
        bundle->x509Auths = x509util_CopyX509Authorities(auths);
    }
    return bundle;
}

spiffebundle_Bundle *
spiffebundle_FromJWTAuthorities(const spiffeid_TrustDomain td,
                                map_string_EVP_PKEY *auths)
{
    spiffebundle_Bundle *bundle = spiffebundle_New(td);

    if(bundle) {
        bundle->jwtAuths = jwtutil_CopyJWTAuthorities(auths);
    }

    return bundle;
}

spiffeid_TrustDomain
spiffebundle_Bundle_TrustDomain(const spiffebundle_Bundle *b)
{
    return b->td;
}

X509 **spiffebundle_Bundle_X509Authorities(spiffebundle_Bundle *b)
{
    mtx_lock(&(b->mtx));
    X509 **auths = x509util_CopyX509Authorities(b->x509Auths);
    mtx_unlock(&(b->mtx));

    return auths;
}

void spiffebundle_Bundle_AddX509Authority(spiffebundle_Bundle *b, X509 *auth)
{
    mtx_lock(&(b->mtx));
    arrput(b->x509Auths, auth);
    mtx_unlock(&(b->mtx));
}

void spiffebundle_Bundle_RemoveX509Authority(spiffebundle_Bundle *b,
                                             const X509 *auth)
{
    mtx_lock(&(b->mtx));
    for(size_t i = 0, size = arrlenu(b->x509Auths); i < size; ++i) {
        if(!X509_cmp(b->x509Auths[i], auth))
            arrdel(b->x509Auths, i);
    }
    mtx_unlock(&(b->mtx));
}

bool spiffebundle_Bundle_HasX509Authority(spiffebundle_Bundle *b,
                                          const X509 *auth)
{
    mtx_lock(&(b->mtx));
    bool present = false;
    for(size_t i = 0, size = arrlenu(b->x509Auths); i < size; ++i) {
        if(!X509_cmp(b->x509Auths[i], auth)) {
            present = true;
            break;
        }
    }
    mtx_unlock(&(b->mtx));

    return present;
}

void spiffebundle_Bundle_SetX509Authorities(spiffebundle_Bundle *b,
                                            X509 **auths)
{
    mtx_lock(&(b->mtx));
    for(size_t i = 0, size = arrlenu(b->x509Auths); i < size; ++i) {
        X509_free(b->x509Auths[i]);
    }
    arrfree(b->x509Auths);
    b->x509Auths = x509util_CopyX509Authorities(auths);
    mtx_unlock(&(b->mtx));
}

map_string_EVP_PKEY *spiffebundle_Bundle_JWTAuthorities(spiffebundle_Bundle *b)
{
    mtx_lock(&(b->mtx));
    map_string_EVP_PKEY *copy_auths = jwtutil_CopyJWTAuthorities(b->jwtAuths);
    mtx_unlock(&(b->mtx));

    return copy_auths;
}

EVP_PKEY *spiffebundle_Bundle_FindJWTAuthority(spiffebundle_Bundle *b,
                                               const char *keyID, bool *suc)
{
    mtx_lock(&(b->mtx));
    EVP_PKEY *pkey = NULL;
    *suc = false;
    int idx = shgeti(b->jwtAuths, keyID);
    if(idx >= 0) {
        pkey = b->jwtAuths[idx].value;
        *suc = true;
    }
    mtx_unlock(&(b->mtx));

    return pkey;
}

bool spiffebundle_Bundle_HasJWTAuthority(spiffebundle_Bundle *b,
                                         const char *keyID)
{
    mtx_lock(&(b->mtx));
    const bool present = shgeti(b->jwtAuths, keyID) >= 0 ? true : false;
    mtx_unlock(&(b->mtx));

    return present;
}

err_t spiffebundle_Bundle_AddJWTAuthority(spiffebundle_Bundle *b,
                                          const char *keyID, EVP_PKEY *auth)
{
    // empty string error
    err_t err = ERROR1;

    if(!empty_str(keyID)) {
        mtx_lock(&(b->mtx));
        shput(b->jwtAuths, keyID, auth);
        err = NO_ERROR;
        mtx_unlock(&(b->mtx));
    }

    return err;
}

void spiffebundle_Bundle_RemoveJWTAuthority(spiffebundle_Bundle *b,
                                            const char *keyID)
{
    mtx_lock(&(b->mtx));
    shdel(b->jwtAuths, keyID);
    mtx_unlock(&(b->mtx));
}

void spiffebundle_Bundle_SetJWTAuthorities(spiffebundle_Bundle *b,
                                           map_string_EVP_PKEY *auths)
{
    mtx_lock(&(b->mtx));
    for(size_t i = 0, size = shlenu(b->jwtAuths); i < size; ++i) {
        EVP_PKEY_free(b->jwtAuths[i].value);
    }
    shfree(b->jwtAuths);
    b->jwtAuths = jwtutil_CopyJWTAuthorities(auths);
    mtx_unlock(&(b->mtx));
}

bool spiffebundle_Bundle_Empty(spiffebundle_Bundle *b)
{
    mtx_lock(&(b->mtx));
    bool empty = (arrlenu(b->x509Auths) == 0) && (shlenu(b->jwtAuths) == 0);
    mtx_unlock(&(b->mtx));

    return empty;
}

struct timespec spiffebundle_Bundle_RefreshHint(spiffebundle_Bundle *b,
                                                bool *suc)
{
    mtx_lock(&(b->mtx));
    struct timespec ts = { 0, 0 };
    *suc = false;

    if(b->refreshHint) {
        ts = *(b->refreshHint);
        *suc = true;
    }
    mtx_unlock(&(b->mtx));

    return ts;
}

void spiffebundle_Bundle_SetRefreshHint(spiffebundle_Bundle *b,
                                        struct timespec *refHint)
{
    mtx_lock(&(b->mtx));
    b->refreshHint = refHint;
    mtx_unlock(&(b->mtx));
}

void spiffebundle_Bundle_ClearRefreshHint(spiffebundle_Bundle *b)
{
    mtx_lock(&(b->mtx));
    b->refreshHint = NULL;
    mtx_unlock(&(b->mtx));
}

uint64_t spiffebundle_Bundle_SequenceNumber(spiffebundle_Bundle *b, bool *suc)
{
    mtx_lock(&(b->mtx));
    uint64_t seqNum = 0;
    *suc = false;

    if(b->seqNumber) {
        seqNum = *(b->seqNumber);
        *suc = true;
    }
    mtx_unlock(&(b->mtx));

    return seqNum;
}

void spiffebundle_Bundle_SetSequenceNumber(spiffebundle_Bundle *b,
                                           uint64_t *seqNumber)
{
    mtx_lock(&(b->mtx));
    b->seqNumber = seqNumber;
    mtx_unlock(&(b->mtx));
}

void spiffebundle_Bundle_ClearSequenceNumber(spiffebundle_Bundle *b)
{
    mtx_lock(&(b->mtx));
    b->seqNumber = NULL;
    mtx_unlock(&(b->mtx));
}

spiffebundle_Bundle *spiffebundle_Bundle_Clone(spiffebundle_Bundle *b)
{
    mtx_lock(&(b->mtx));
    spiffebundle_Bundle *nbundle = spiffebundle_New(b->td);
    nbundle->refreshHint = spiffebundle_copyRefreshHint(b->refreshHint);
    nbundle->seqNumber = spiffebundle_copySequenceNumber(b->seqNumber);
    nbundle->x509Auths = x509util_CopyX509Authorities(b->x509Auths);
    nbundle->jwtAuths = jwtutil_CopyJWTAuthorities(b->jwtAuths);
    mtx_unlock(&(b->mtx));

    return nbundle;
}

x509bundle_Bundle *spiffebundle_Bundle_X509Bundle(spiffebundle_Bundle *b)
{
    mtx_lock(&(b->mtx));
    x509bundle_Bundle *x509bundle
        = x509bundle_FromX509Authorities(b->td, b->x509Auths);
    mtx_unlock(&(b->mtx));

    return x509bundle;
}

jwtbundle_Bundle *spiffebundle_Bundle_JWTBundle(spiffebundle_Bundle *b)
{
    mtx_lock(&(b->mtx));
    jwtbundle_Bundle *jwtbundle
        = jwtbundle_FromJWTAuthorities(b->td, b->jwtAuths);
    mtx_unlock(&(b->mtx));

    return jwtbundle;
}

spiffebundle_Bundle *spiffebundle_Bundle_GetBundleForTrustDomain(
    spiffebundle_Bundle *b, const spiffeid_TrustDomain td, err_t *err)
{
    mtx_lock(&(b->mtx));
    spiffebundle_Bundle *bundle = NULL;
    // trust domain not available
    *err = ERROR1;
    if(!strcmp(b->td.name, td.name)) {
        bundle = b;
        *err = NO_ERROR;
    }
    mtx_unlock(&(b->mtx));

    return bundle;
}

x509bundle_Bundle *spiffebundle_Bundle_GetX509BundleForTrustDomain(
    spiffebundle_Bundle *b, const spiffeid_TrustDomain td, err_t *err)
{
    mtx_lock(&(b->mtx));
    x509bundle_Bundle *bundle = NULL;
    // trust domain not available
    *err = ERROR1;
    if(!strcmp(b->td.name, td.name)) {
        bundle = spiffebundle_Bundle_X509Bundle(b);
        *err = NO_ERROR;
    }
    mtx_unlock(&(b->mtx));

    return bundle;
}

jwtbundle_Bundle *spiffebundle_Bundle_GetJWTBundleForTrustDomain(
    spiffebundle_Bundle *b, const spiffeid_TrustDomain td, err_t *err)
{
    mtx_lock(&(b->mtx));
    jwtbundle_Bundle *bundle = NULL;
    // trust domain not available
    *err = ERROR1;
    if(!strcmp(b->td.name, td.name)) {
        bundle = spiffebundle_Bundle_JWTBundle(b);
        *err = NO_ERROR;
    }
    mtx_unlock(&(b->mtx));

    return bundle;
}

bool spiffebundle_Bundle_Equal(const spiffebundle_Bundle *b1,
                               const spiffebundle_Bundle *b2)
{
    if(b1 && b2) {
        return !strcmp(b1->td.name, b2->td.name)
               && spiffebundle_refreshHintEqual(b1->refreshHint,
                                                b2->refreshHint)
               && spiffebundle_sequenceNumberEqual(b1->seqNumber,
                                                   b2->seqNumber)
               && x509util_CertsEqual(b1->x509Auths, b2->x509Auths)
               && jwtutil_JWTAuthoritiesEqual(b1->jwtAuths, b2->jwtAuths);
    } else
        return b1 == b2;
}

bool spiffebundle_refreshHintEqual(const struct timespec *t1,
                                   const struct timespec *t2)
{
    if(t1 && t2) {
        return (t1->tv_nsec == t2->tv_nsec) && (t1->tv_sec == t2->tv_sec);
    }

    return t1 == t2;
}

bool spiffebundle_sequenceNumberEqual(const uint64_t *a, const uint64_t *b)
{
    if(a && b) {
        return *a == *b;
    }

    return a == b;
}

struct timespec *spiffebundle_copyRefreshHint(const struct timespec *ts)
{
    if(ts) {
        struct timespec *new_ts = malloc(sizeof *new_ts);
        memcpy(new_ts, ts, sizeof *new_ts);

        return new_ts;
    }

    return NULL;
}

uint64_t *spiffebundle_copySequenceNumber(const uint64_t *seqNum)
{
    if(seqNum) {
        uint64_t *new_seqNum = malloc(sizeof *new_seqNum);
        *new_seqNum = *seqNum;

        return new_seqNum;
    }

    return NULL;
}
