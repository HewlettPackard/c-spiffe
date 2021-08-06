#include "c-spiffe/bundle/jwtbundle/set.h"
#include <stdarg.h>
#include <stdio.h>

jwtbundle_Set *jwtbundle_NewSet(const int n_args, ...)
{
    jwtbundle_Set *set = malloc(sizeof *set);
    mtx_init(&(set->mtx), mtx_plain);
    set->bundles = NULL;
    sh_new_strdup(set->bundles);

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

err_t jwtbundle_Set_print_BIO(jwtbundle_Set *s, int offset, BIO *out)
{
    if(offset < 0) {
        return ERR_BAD_REQUEST;
    } else if(s && out) {
        mtx_lock(&s->mtx); // lock the mutex so we guarantee no one changes the
                           // set before we print.
        BIO_indent(out, offset, 20);
        BIO_printf(out, "Bundle Set: [\n");
        err_t error = NO_ERROR;
        for(size_t i = 0, size = shlenu(s->bundles);
            i < size && error == NO_ERROR; ++i) {
            // print using ssl functions.
            error = jwtbundle_Bundle_print_BIO(s->bundles[i].value, offset + 1,
                                               out);
        }
        BIO_indent(out, offset, 20);
        BIO_printf(out, "]\n");

        mtx_unlock(&s->mtx); // unlock bundle mutex.
        return error;
    } else if(!s) {
        return ERR_NULL_DATA;
    } else {
        return ERR_NULL_BIO;
    }
}

err_t jwtbundle_Set_print_fd(jwtbundle_Set *s, int offset, FILE *fd)
{
    BIO *out = BIO_new_fp(fd, BIO_NOCLOSE);
    if(!out) {
        return ERR_NULL_DATA;
    }
    err_t error = jwtbundle_Set_print_BIO(s, offset, out);
    BIO_free(out);
    return error;
}

err_t jwtbundle_Set_print_stdout(jwtbundle_Set *s, int offset)
{
    // call print with default params.
    return jwtbundle_Set_print_fd(s, offset, stdout);
}

err_t jwtbundle_Set_Print(jwtbundle_Set *s)
{
    // call print with default params.
    return jwtbundle_Set_print_stdout(s, 0);
}

jwtbundle_Bundle *jwtbundle_Set_GetJWTBundleForTrustDomain(
    jwtbundle_Set *s, const spiffeid_TrustDomain td, err_t *err)
{
    mtx_lock(&(s->mtx));
    jwtbundle_Bundle *bundle = NULL;
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

jwtbundle_Set *jwtbundle_Set_Clone(jwtbundle_Set *set)
{
    jwtbundle_Set *ret = jwtbundle_NewSet(0);
    mtx_lock(&(set->mtx));
    for(size_t i = 0, size = hmlenu(set->bundles); i < size; ++i) {
        jwtbundle_Bundle *bundle
            = jwtbundle_Bundle_Clone(set->bundles[i].value);
        jwtbundle_Set_Add(ret, bundle);
    }
    mtx_unlock(&(set->mtx));
    return ret;
}

void jwtbundle_Set_Free(jwtbundle_Set *s)
{
    if(s) {
        for(size_t i = 0, size = shlenu(s->bundles); i < size; ++i) {
            jwtbundle_Bundle_Free(s->bundles[i].value);
        }
        shfree(s->bundles);

        free(s);
    }
}
