#include "bundle/x509bundle/src/set.h"
#include <stdarg.h>

x509bundle_Set *x509bundle_NewSet(const int n_args, ...)
{
    x509bundle_Set *set = malloc(sizeof *set);
    mtx_init(&(set->mtx), mtx_plain);
    set->bundles = NULL;
    sh_new_strdup(set->bundles);

    va_list args;
    va_start(args, n_args);

    for(int i = 0; i < n_args; ++i) {
        x509bundle_Bundle *bundle = va_arg(args, x509bundle_Bundle *);
        shput(set->bundles, bundle->td.name, bundle);
    }

    va_end(args);

    return set;
}

void x509bundle_Set_Add(x509bundle_Set *s, x509bundle_Bundle *bundle)
{
    mtx_lock(&(s->mtx));
    shput(s->bundles, bundle->td.name, bundle);
    mtx_unlock(&(s->mtx));
}

void x509bundle_Set_Remove(x509bundle_Set *s, const spiffeid_TrustDomain td)
{
    mtx_lock(&(s->mtx));
    shdel(s->bundles, td.name);
    mtx_unlock(&(s->mtx));
}

bool x509bundle_Set_Has(x509bundle_Set *s, const spiffeid_TrustDomain td)
{
    mtx_lock(&(s->mtx));
    const bool present = shgeti(s->bundles, td.name) >= 0 ? true : false;
    mtx_unlock(&(s->mtx));

    return present;
}

x509bundle_Bundle *x509bundle_Set_Get(x509bundle_Set *s,
                                      const spiffeid_TrustDomain td, bool *suc)
{
    mtx_lock(&(s->mtx));
    *suc = false;
    x509bundle_Bundle *bundle = NULL;
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
    const x509bundle_Bundle **b1 = (const x509bundle_Bundle **) v1,
                            **b2 = (const x509bundle_Bundle **) v2;
    return strcmp((*b1)->td.name, (*b2)->td.name);
}

x509bundle_Bundle **x509bundle_Set_Bundles(x509bundle_Set *s)
{
    mtx_lock(&(s->mtx));
    x509bundle_Bundle **bundle_arr = NULL;

    for(size_t i = 0, size = shlenu(s->bundles); i < size; ++i) {
        arrput(bundle_arr, s->bundles[i].value);
    }

    qsort(bundle_arr, arrlenu(bundle_arr), sizeof(bundle_arr[0]), cmp_bundle);

    mtx_unlock(&(s->mtx));

    return bundle_arr;
}

uint32_t x509bundle_Set_Len(x509bundle_Set *s)
{
    mtx_lock(&(s->mtx));
    const uint32_t len = shlenu(s->bundles);
    mtx_unlock(&(s->mtx));

    return len;
}

x509bundle_Bundle *x509bundle_Set_GetX509BundleForTrustDomain(
    x509bundle_Set *s, const spiffeid_TrustDomain td, err_t *err)
{
    mtx_lock(&(s->mtx));
    x509bundle_Bundle *bundle = NULL;
    // trust domain not available
    *err = ERROR1;
    int idx = shgeti(s->bundles, td.name);
    if(idx >= 0) {
        bundle = s->bundles[idx].value;
        *err = NO_ERROR;
    }
    mtx_unlock(&(s->mtx));

    return bundle;
}

void x509bundle_Set_Free(x509bundle_Set *s)
{
    if(s) {
        for(size_t i = 0, size = shlenu(s->bundles); i < size; ++i) {
            x509bundle_Bundle_Free(s->bundles[i].value);
        }
        shfree(s->bundles);

        free(s);
    }
}
