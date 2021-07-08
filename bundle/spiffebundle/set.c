#include "c-spiffe/bundle/spiffebundle/set.h"

spiffebundle_Set *spiffebundle_NewSet(int n_args, ...)
{
    spiffebundle_Set *set = malloc(sizeof *set);
    mtx_init(&(set->mtx), mtx_plain);
    set->bundles = NULL;
    sh_new_strdup(set->bundles);

    va_list args;
    va_start(args, n_args);

    for(int i = 0; i < n_args; ++i) {
        spiffebundle_Bundle *bundle = va_arg(args, spiffebundle_Bundle *);
        shput(set->bundles, bundle->td.name, bundle);
    }

    va_end(args);

    return set;
}

void spiffebundle_Set_Add(spiffebundle_Set *s, spiffebundle_Bundle *bundle)
{
    mtx_lock(&(s->mtx));
    shput(s->bundles, bundle->td.name, bundle);
    mtx_unlock(&(s->mtx));
}

void spiffebundle_Set_Remove(spiffebundle_Set *s,
                             const spiffeid_TrustDomain td)
{
    mtx_lock(&(s->mtx));
    shdel(s->bundles, td.name);
    mtx_unlock(&(s->mtx));
}

bool spiffebundle_Set_Has(spiffebundle_Set *s, const spiffeid_TrustDomain td)
{
    mtx_lock(&(s->mtx));
    const bool present = shgeti(s->bundles, td.name) >= 0 ? true : false;
    mtx_unlock(&(s->mtx));

    return present;
}

spiffebundle_Bundle *spiffebundle_Set_Get(spiffebundle_Set *s,
                                          const spiffeid_TrustDomain td,
                                          bool *suc)
{
    mtx_lock(&(s->mtx));
    *suc = false;
    spiffebundle_Bundle *bundle = NULL;
    int idx = shgeti(s->bundles, td.name);
    if(idx >= 0) {
        bundle = s->bundles[idx].value;
        *suc = true;
    }
    mtx_unlock(&(s->mtx));

    return bundle;
}

static int cmp_bundle(const void *v1, const void *v2)
{
    const spiffebundle_Bundle **b1 = (const spiffebundle_Bundle **) v1,
                              **b2 = (const spiffebundle_Bundle **) v2;
    return strcmp((*b1)->td.name, (*b2)->td.name);
}

spiffebundle_Bundle **spiffebundle_Set_Bundles(spiffebundle_Set *s)
{
    mtx_lock(&(s->mtx));
    spiffebundle_Bundle **bundle_arr = NULL;

    for(size_t i = 0, size = shlenu(s->bundles); i < size; ++i) {
        arrput(bundle_arr, s->bundles[i].value);
    }

    qsort(bundle_arr, arrlenu(bundle_arr), sizeof(bundle_arr[0]), cmp_bundle);

    mtx_unlock(&(s->mtx));

    return bundle_arr;
}

uint32_t spiffebundle_Set_Len(spiffebundle_Set *s)
{
    mtx_lock(&(s->mtx));
    const uint32_t len = shlenu(s->bundles);
    mtx_unlock(&(s->mtx));

    return len;
}

spiffebundle_Bundle *spiffebundle_Set_GetBundleForTrustDomain(
    spiffebundle_Set *s, const spiffeid_TrustDomain td, err_t *err)
{
    mtx_lock(&(s->mtx));
    spiffebundle_Bundle *bundle = NULL;
    // trust domain not available
    *err = ERR_TRUSTDOMAIN_NOTAVAILABLE;
    int idx = shgeti(s->bundles, td.name);
    if(idx >= 0) {
        bundle = s->bundles[idx].value;
        *err = NO_ERROR;
    }
    mtx_unlock(&(s->mtx));

    return bundle;
}

x509bundle_Bundle *spiffebundle_Set_GetX509BundleForTrustDomain(
    spiffebundle_Set *s, const spiffeid_TrustDomain td, err_t *err)
{
    mtx_lock(&(s->mtx));
    x509bundle_Bundle *bundle = NULL;
    // trust domain not available
    *err = ERR_TRUSTDOMAIN_NOTAVAILABLE;
    int idx = shgeti(s->bundles, td.name);
    if(idx >= 0) {
        bundle = spiffebundle_Bundle_X509Bundle(s->bundles[idx].value);
        *err = NO_ERROR;
    }
    mtx_unlock(&(s->mtx));

    return bundle;
}

jwtbundle_Bundle *spiffebundle_Set_GetJWTBundleForTrustDomain(
    spiffebundle_Set *s, const spiffeid_TrustDomain td, err_t *err)
{
    mtx_lock(&(s->mtx));
    jwtbundle_Bundle *bundle = NULL;
    // trust domain not available
    *err = ERR_TRUSTDOMAIN_NOTAVAILABLE;
    int idx = shgeti(s->bundles, td.name);
    if(idx >= 0) {
        bundle = spiffebundle_Bundle_JWTBundle(s->bundles[idx].value);
        *err = NO_ERROR;
    }
    mtx_unlock(&(s->mtx));

    return bundle;
}

void spiffebundle_Set_Free(spiffebundle_Set *s)
{
    if(s) {
        for(size_t i = 0, size = shlenu(s->bundles); i < size; ++i) {
            spiffebundle_Bundle_Free(s->bundles[i].value);
        }
        shfree(s->bundles);

        free(s);
    }
}
