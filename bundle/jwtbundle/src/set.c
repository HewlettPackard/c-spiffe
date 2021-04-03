#include "bundle/jwtbundle/src/set.h"
#include <stdarg.h>

jwtbundle_Set *jwtbundle_NewSet(const int n_args, ...)
{
    jwtbundle_Set *set = malloc(sizeof *set);
    mtx_init(&(set->mtx), mtx_plain);
    set->bundles = NULL;

    va_list args;
    va_start(args, n_args);

    for(int i = 0; i < n_args; ++i) {
        jwtbundle_Bundle *bundle = va_arg(args, jwtbundle_Bundle *);
        shput(set->bundles, bundle->td.name, bundle);
    }

    va_end(args);

    return set;
}

void jwtbundle_Set_Add(jwtbundle_Set *s, jwtbundle_Bundle *bundle)
{
    mtx_lock(&(s->mtx));
    shput(s->bundles, bundle->td.name, bundle);
    mtx_unlock(&(s->mtx));
}

void jwtbundle_Set_Remove(jwtbundle_Set *s, const spiffeid_TrustDomain td)
{
    mtx_lock(&(s->mtx));
    shdel(s->bundles, td.name);
    mtx_unlock(&(s->mtx));
}

bool jwtbundle_Set_Has(jwtbundle_Set *s, const spiffeid_TrustDomain td)
{
    mtx_lock(&(s->mtx));
    const bool present = shgeti(s->bundles, td.name) >= 0 ? true : false;
    mtx_unlock(&(s->mtx));

    return present;
}

jwtbundle_Bundle *jwtbundle_Set_Get(jwtbundle_Set *s,
                                    const spiffeid_TrustDomain td, bool *suc)
{
    mtx_lock(&(s->mtx));
    *suc = false;
    jwtbundle_Bundle *bundle = NULL;
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
    const jwtbundle_Bundle **b1 = (const jwtbundle_Bundle **) v1,
                           **b2 = (const jwtbundle_Bundle **) v2;
    return strcmp((*b1)->td.name, (*b2)->td.name);
}

jwtbundle_Bundle **jwtbundle_Set_Bundles(jwtbundle_Set *s)
{
    mtx_lock(&(s->mtx));
    jwtbundle_Bundle **bundle_arr = NULL;

    for(size_t i = 0, size = shlenu(s->bundles); i < size; ++i) {
        arrput(bundle_arr, s->bundles[i].value);
    }

    qsort(bundle_arr, arrlenu(bundle_arr), sizeof(bundle_arr[0]), cmp_bundle);

    mtx_unlock(&(s->mtx));

    return bundle_arr;
}

uint32_t jwtbundle_Set_Len(jwtbundle_Set *s)
{
    mtx_lock(&(s->mtx));
    const uint32_t len = shlenu(s->bundles);
    mtx_unlock(&(s->mtx));

    return len;
}

void jwtbundle_Set_print_(jwtbundle_Set *s, int offset, BIO *out)
{
    if(s) {
        mtx_lock(&s->mtx); // lock the mutex so we guarantee no one changes the
                           // set before we print.
        bool should_free = false;
        if(!out) { // if not provided, allocate a new BIO*
            out = BIO_new_fd(stdout, BIO_NOCLOSE);
            should_free = true; // and take note so we free it later
        }
        char *spaces = calloc(offset + 1, sizeof(char));
        for(int i = 0; i < offset; ++i) {
            spaces[i] = ' ';
        }
        BIO_printf(out, "%sBundle Set: [\n", spaces);

        for(size_t i = 0, size = shlenu(s->bundles); i < size; ++i) {
            // print using ssl functions.
            jwtbundle_Bundle_print_(s->bundles[i].value, offset + 1, out);
        }
        BIO_printf(out, "%s]\n", spaces);

        if(should_free) {
            BIO_free(out);
        }

        free(spaces);

        mtx_unlock(&s->mtx); // unlock bundle mutex.
    }
}

void jwtbundle_Set_Print(jwtbundle_Set *s)
{
    // call print with default params.
    jwtbundle_Set_print_(s, 0, NULL);
}

jwtbundle_Bundle *jwtbundle_Set_GetJWTBundleForTrustDomain(
    jwtbundle_Set *s, const spiffeid_TrustDomain td, err_t *err)
{
    mtx_lock(&(s->mtx));
    jwtbundle_Bundle *bundle = NULL;
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

void jwtbundle_Set_Free(jwtbundle_Set *s)
{
    if(s) {
        for(size_t i = 0, size = shlenu(s->bundles); i < size; ++i) {
            jwtbundle_Bundle_Free(s->bundles[i].value);
        }

        free(s);
    }
}
