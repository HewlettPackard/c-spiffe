#include "c-spiffe/bundle/spiffebundle/bundle.h"
#include "c-spiffe/internal/jwtutil/util.h"
#include "c-spiffe/internal/x509util/util.h"
#include "c-spiffe/utils/util.h"

spiffebundle_Bundle *spiffebundle_New(const spiffeid_TrustDomain td)
{
    spiffebundle_Bundle *bundle = malloc(sizeof *bundle);
    if(bundle) {
        bundle->td.name = string_new(td.name);
        mtx_init(&(bundle->mtx), mtx_plain);
        bundle->jwt_auths = NULL;
        sh_new_strdup(bundle->jwt_auths);
        bundle->x509_auths = NULL;
        bundle->refresh_hint = (struct timespec){ .tv_sec = -1, .tv_nsec = 0 };
        bundle->seq_number = -1;
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

        bundleptr = spiffebundle_Parse(td, buffer, err);
        arrfree(buffer);
    } else {
        *err = ERR_OPENING;
    }

    return bundleptr;
}

spiffebundle_Bundle *spiffebundle_Parse(const spiffeid_TrustDomain td,
                                        const char *bundle_bytes, err_t *err)
{
    spiffebundle_Bundle *bundleptr = NULL;
    if(td.name && bundle_bytes) {
        jwtutil_JWKS jwks = jwtutil_ParseJWKS(bundle_bytes, err);

        if(!(*err)) {
            *err = NO_ERROR;

            bundleptr = spiffebundle_New(td);
            shfree(bundleptr->jwt_auths);
            bundleptr->jwt_auths = jwks.jwt_auths;
            bundleptr->x509_auths = jwks.x509_auths;

            json_t *ref_hint_json
                = json_object_get(jwks.root, "spiffe_refresh_hint");
            json_t *seq_num_json
                = json_object_get(jwks.root, "spiffe_sequence");

            if(ref_hint_json) {
                long long ref_hint = json_typeof(ref_hint_json) == JSON_INTEGER
                                         ? json_integer_value(ref_hint_json)
                                         : 0LL;
                if(ref_hint >= 0LL) {
                    bundleptr->refresh_hint.tv_sec = (time_t) ref_hint;
                    bundleptr->refresh_hint.tv_nsec = 0L;
                }
            }
            if(seq_num_json) {
                long long seq_num = json_typeof(seq_num_json) == JSON_INTEGER
                                        ? json_integer_value(seq_num_json)
                                        : 0LL;
                if(seq_num >= 0LL) {
                    bundleptr->seq_number = seq_num;
                }
            }

        } else {
            // could not parse jwks
            *err = ERR_PARSING;
        }
    } else {
        // NULL error
        *err = ERR_NULL;
    }

    return bundleptr;
}

spiffebundle_Bundle *spiffebundle_FromX509Bundle(x509bundle_Bundle *x509bundle)
{
    spiffebundle_Bundle *mbundle
        = spiffebundle_New(x509bundle_Bundle_TrustDomain(x509bundle));

    if(mbundle) {
        mbundle->x509_auths = x509bundle_Bundle_X509Authorities(x509bundle);
    }

    return mbundle;
}

spiffebundle_Bundle *spiffebundle_FromJWTBundle(jwtbundle_Bundle *jwtbundle)
{
    spiffebundle_Bundle *mbundle
        = spiffebundle_New(jwtbundle_Bundle_TrustDomain(jwtbundle));

    if(mbundle) {
        shfree(mbundle->jwt_auths);
        mbundle->jwt_auths = jwtbundle_Bundle_JWTAuthorities(jwtbundle);
    }

    return mbundle;
}

spiffebundle_Bundle *
spiffebundle_FromX509Authorities(const spiffeid_TrustDomain td, X509 **auths)
{
    spiffebundle_Bundle *bundle = spiffebundle_New(td);

    if(bundle) {
        bundle->x509_auths = x509util_CopyX509Authorities(auths);
    }
    return bundle;
}

spiffebundle_Bundle *
spiffebundle_FromJWTAuthorities(const spiffeid_TrustDomain td,
                                map_string_EVP_PKEY *auths)
{
    spiffebundle_Bundle *bundle = spiffebundle_New(td);

    if(bundle) {
        shfree(bundle->jwt_auths);
        bundle->jwt_auths = jwtutil_CopyJWTAuthorities(auths);
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
    X509 **auths = x509util_CopyX509Authorities(b->x509_auths);
    mtx_unlock(&(b->mtx));

    return auths;
}

void spiffebundle_Bundle_AddX509Authority(spiffebundle_Bundle *b, X509 *auth)
{
    mtx_lock(&(b->mtx));
    bool suc = false;
    // searches for certificate
    for(size_t i = 0, size = arrlenu(b->x509_auths); i < size; ++i) {
        if(!X509_cmp(b->x509_auths[i], auth)) {
            // b->auths[i] == auth
            suc = true;
            break;
        }
    }
    if(!suc) {
        X509_up_ref(auth);
        arrput(b->x509_auths, auth);
    }
    mtx_unlock(&(b->mtx));
}

void spiffebundle_Bundle_RemoveX509Authority(spiffebundle_Bundle *b,
                                             const X509 *auth)
{
    mtx_lock(&(b->mtx));
    for(size_t i = 0, size = arrlenu(b->x509_auths); i < size; ++i) {
        if(!X509_cmp(b->x509_auths[i], auth)) {
            X509_free(b->x509_auths[i]);
            arrdel(b->x509_auths, i);
            break;
        }
    }
    mtx_unlock(&(b->mtx));
}

bool spiffebundle_Bundle_HasX509Authority(spiffebundle_Bundle *b,
                                          const X509 *auth)
{
    mtx_lock(&(b->mtx));
    bool present = false;
    for(size_t i = 0, size = arrlenu(b->x509_auths); i < size; ++i) {
        if(!X509_cmp(b->x509_auths[i], auth)) {
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
    for(size_t i = 0, size = arrlenu(b->x509_auths); i < size; ++i) {
        X509_free(b->x509_auths[i]);
    }
    arrfree(b->x509_auths);
    b->x509_auths = x509util_CopyX509Authorities(auths);
    mtx_unlock(&(b->mtx));
}

map_string_EVP_PKEY *spiffebundle_Bundle_JWTAuthorities(spiffebundle_Bundle *b)
{
    mtx_lock(&(b->mtx));
    map_string_EVP_PKEY *copy_auths = jwtutil_CopyJWTAuthorities(b->jwt_auths);
    mtx_unlock(&(b->mtx));

    return copy_auths;
}

EVP_PKEY *spiffebundle_Bundle_FindJWTAuthority(spiffebundle_Bundle *b,
                                               const char *keyID, bool *suc)
{
    mtx_lock(&(b->mtx));
    EVP_PKEY *pkey = NULL;
    *suc = false;
    int idx = shgeti(b->jwt_auths, keyID);
    if(idx >= 0) {
        pkey = b->jwt_auths[idx].value;
        *suc = true;
    }
    mtx_unlock(&(b->mtx));

    return pkey;
}

bool spiffebundle_Bundle_HasJWTAuthority(spiffebundle_Bundle *b,
                                         const char *keyID)
{
    mtx_lock(&(b->mtx));
    const bool present = shgeti(b->jwt_auths, keyID) >= 0 ? true : false;
    mtx_unlock(&(b->mtx));

    return present;
}

err_t spiffebundle_Bundle_AddJWTAuthority(spiffebundle_Bundle *b,
                                          const char *keyID, EVP_PKEY *auth)
{
    // empty string error
    err_t err = ERR_EMPTY_DATA;

    if(!empty_str(keyID)) {
        mtx_lock(&(b->mtx));
        if(shgeti(b->jwt_auths, keyID) < 0) {
            EVP_PKEY_up_ref(auth);
            shput(b->jwt_auths, keyID, auth);
        }
        err = NO_ERROR;
        mtx_unlock(&(b->mtx));
    }

    return err;
}

void spiffebundle_Bundle_RemoveJWTAuthority(spiffebundle_Bundle *b,
                                            const char *keyID)
{
    mtx_lock(&(b->mtx));
    shdel(b->jwt_auths, keyID);
    mtx_unlock(&(b->mtx));
}

void spiffebundle_Bundle_SetJWTAuthorities(spiffebundle_Bundle *b,
                                           map_string_EVP_PKEY *auths)
{
    mtx_lock(&(b->mtx));
    for(size_t i = 0, size = shlenu(b->jwt_auths); i < size; ++i) {
        EVP_PKEY_free(b->jwt_auths[i].value);
    }
    shfree(b->jwt_auths);
    b->jwt_auths = jwtutil_CopyJWTAuthorities(auths);
    mtx_unlock(&(b->mtx));
}

bool spiffebundle_Bundle_Empty(spiffebundle_Bundle *b)
{
    mtx_lock(&(b->mtx));
    bool empty = (arrlenu(b->x509_auths) == 0) && (shlenu(b->jwt_auths) == 0);
    mtx_unlock(&(b->mtx));

    return empty;
}

struct timespec spiffebundle_Bundle_RefreshHint(spiffebundle_Bundle *b,
                                                bool *suc)
{
    mtx_lock(&(b->mtx));
    *suc = (b->refresh_hint.tv_sec >= 0);
    mtx_unlock(&(b->mtx));

    return b->refresh_hint;
}

void spiffebundle_Bundle_SetRefreshHint(spiffebundle_Bundle *b,
                                        const struct timespec *refHint)
{
    mtx_lock(&(b->mtx));
    b->refresh_hint = *refHint;
    mtx_unlock(&(b->mtx));
}

void spiffebundle_Bundle_ClearRefreshHint(spiffebundle_Bundle *b)
{
    mtx_lock(&(b->mtx));
    b->refresh_hint = (struct timespec){ .tv_sec = -1, .tv_nsec = 0 };
    mtx_unlock(&(b->mtx));
}

string_t spiffebundle_Bundle_Marshal(spiffebundle_Bundle *b, err_t *err)
{
    if(!b){
        *err = ERR_NULL_BUNDLE;
        return NULL;
    }
    mtx_lock(&(b->mtx));
    jwtutil_JWKS jwks
        = { .root = NULL,
            .jwt_auths = jwtutil_CopyJWTAuthorities(b->jwt_auths),
            .x509_auths = x509util_CopyX509Authorities(b->x509_auths) };
    string_t str = jwtutil_JWKS_Marshal(&jwks, err);
    if(jwks.root && !(*err)) {
        if(b->refresh_hint.tv_sec >= 0) {
            json_object_set_new(jwks.root, "spiffe_refresh_hint",
                                json_integer(b->refresh_hint.tv_sec));
        }
        if(b->seq_number >= 0) {
            json_object_set_new(jwks.root, "spiffe_sequence",
                                json_integer(b->seq_number));
        }
        arrfree(str);
        str = jwtutil_JWKS_Marshal(&jwks, err);
    }
    jwtutil_JWKS_Free(&jwks);
    mtx_unlock(&(b->mtx));

    return str;
}

int64_t spiffebundle_Bundle_SequenceNumber(spiffebundle_Bundle *b, bool *suc)
{
    mtx_lock(&(b->mtx));
    *suc = (b->seq_number >= 0);
    mtx_unlock(&(b->mtx));

    return b->seq_number;
}

void spiffebundle_Bundle_SetSequenceNumber(spiffebundle_Bundle *b,
                                           const int64_t seq_number)
{
    mtx_lock(&(b->mtx));
    b->seq_number = seq_number;
    mtx_unlock(&(b->mtx));
}

void spiffebundle_Bundle_ClearSequenceNumber(spiffebundle_Bundle *b)
{
    mtx_lock(&(b->mtx));
    b->seq_number = -1;
    mtx_unlock(&(b->mtx));
}

spiffebundle_Bundle *spiffebundle_Bundle_Clone(spiffebundle_Bundle *b)
{
    mtx_lock(&(b->mtx));
    spiffebundle_Bundle *mbundle = spiffebundle_New(b->td);
    mbundle->refresh_hint = spiffebundle_copyRefreshHint(&(b->refresh_hint));
    mbundle->seq_number = b->seq_number;
    mbundle->x509_auths = x509util_CopyX509Authorities(b->x509_auths);
    mbundle->jwt_auths = jwtutil_CopyJWTAuthorities(b->jwt_auths);
    mtx_unlock(&(b->mtx));

    return mbundle;
}

x509bundle_Bundle *spiffebundle_Bundle_X509Bundle(spiffebundle_Bundle *b)
{
    mtx_lock(&(b->mtx));
    x509bundle_Bundle *x509bundle
        = x509bundle_FromX509Authorities(b->td, b->x509_auths);
    mtx_unlock(&(b->mtx));

    return x509bundle;
}

jwtbundle_Bundle *spiffebundle_Bundle_JWTBundle(spiffebundle_Bundle *b)
{
    mtx_lock(&(b->mtx));
    jwtbundle_Bundle *jwtbundle
        = jwtbundle_FromJWTAuthorities(b->td, b->jwt_auths);
    mtx_unlock(&(b->mtx));

    return jwtbundle;
}

spiffebundle_Bundle *spiffebundle_Bundle_GetBundleForTrustDomain(
    spiffebundle_Bundle *b, const spiffeid_TrustDomain td, err_t *err)
{
    mtx_lock(&(b->mtx));
    spiffebundle_Bundle *bundle = NULL;
    // trust domain not available
    *err = ERR_TRUSTDOMAIN_NOTAVAILABLE;
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
    *err = ERR_TRUSTDOMAIN_NOTAVAILABLE;
    if(!strcmp(b->td.name, td.name)) {
        bundle = x509bundle_FromX509Authorities(b->td, b->x509_auths);
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
    *err = ERR_TRUSTDOMAIN_NOTAVAILABLE;
    if(!strcmp(b->td.name, td.name)) {
        bundle = jwtbundle_FromJWTAuthorities(b->td, b->jwt_auths);
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
               && spiffebundle_refreshHintEqual(&(b1->refresh_hint),
                                                &(b2->refresh_hint))
               && spiffebundle_sequenceNumberEqual(b1->seq_number,
                                                   b2->seq_number)
               && x509util_CertsEqual(b1->x509_auths, b2->x509_auths)
               && jwtutil_JWTAuthoritiesEqual(b1->jwt_auths, b2->jwt_auths);
    } else {
        return b1 == b2;
    }
}

bool spiffebundle_refreshHintEqual(const struct timespec *t1,
                                   const struct timespec *t2)
{
    if(t1 && t2) {
        return (t1->tv_nsec == t2->tv_nsec) && (t1->tv_sec == t2->tv_sec);
    }

    return t1 == t2;
}

bool spiffebundle_sequenceNumberEqual(const int64_t a, const int64_t b)
{
    return a == b;
}

struct timespec spiffebundle_copyRefreshHint(const struct timespec *ts)
{
    return *ts;
}

void spiffebundle_Bundle_Free(spiffebundle_Bundle *b)
{
    if(b) {
        // mtx_destroy(&(b->mtx));
        for(size_t i = 0, size = shlenu(b->jwt_auths); i < size; ++i) {
            EVP_PKEY_free(b->jwt_auths[i].value);
        }
        shfree(b->jwt_auths);
        for(size_t i = 0, size = arrlenu(b->x509_auths); i < size; ++i) {
            X509_free(b->x509_auths[i]);
        }
        arrfree(b->x509_auths);
        spiffeid_TrustDomain_Free(&(b->td));
        free(b);
    }
}

