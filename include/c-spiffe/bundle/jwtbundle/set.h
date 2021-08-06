#ifndef INCLUDE_BUNDLE_JWTBUNDLE_SET_H
#define INCLUDE_BUNDLE_JWTBUNDLE_SET_H

#include "c-spiffe/bundle/jwtbundle/bundle.h"
// qsort algorithm
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    string_t key;
    jwtbundle_Bundle *value;
} map_string_jwtbundle_Bundle;

/** Set is a set of bundles, keyed by trust domain. */
typedef struct {
    /** map of bundles */
    map_string_jwtbundle_Bundle *bundles;
    /** mutex */
    mtx_t mtx;
} jwtbundle_Set;

/**
 * Creates a new set of JWT bundles from a list of objects.
 *
 * \param n [in] The number of following arguments.
 * \param ... [in] List of n JWT bundle object pointers.
 * \returns A set of JWT bundles with the given objects.
 */
jwtbundle_Set *jwtbundle_NewSet(const int n_args, ...);

/**
 * Adds a JWT bundle to the set. If the bundle already exists in the set
 * for the Trust Domain, the existing bundle is replaced.
 *
 * \param set [in] Set of JWT bundles object pointer.
 * \param bundle [in] JWT Bundle object pointer.
 */
void jwtbundle_Set_Add(jwtbundle_Set *s, jwtbundle_Bundle *bundle);

/**
 * Removes a JWT bundle to the set for the given Trust Domain.
 *
 * \param set [in] Set of JWT bundles object pointer.
 * \param td [in] Trust Domain object.
 */
void jwtbundle_Set_Remove(jwtbundle_Set *s, const spiffeid_TrustDomain td);

/**
 * Copies the content of a bundle set.
 *
 * \param set [in] JWT Bundle Set object pointer.
 * \returns a copy of the set. Must be freed using jwtbundle_Set_Free
 * function.
 */
jwtbundle_Set *jwtbundle_Set_Clone(jwtbundle_Set *set);

/**
 * Checks if a bundle belongs to the set.
 *
 * \param set [in] Set of JWT bundles object pointer.
 * \param td [in] Trust Domain object.
 * \returns <tt>true</tt> if there is a bundle for the given Trust Domain,
 * <tt>false</tt> otherwise.
 */
bool jwtbundle_Set_Has(jwtbundle_Set *s, const spiffeid_TrustDomain td);

/**
 * Gets a JWT bundle from the set for a given Trust Domain.
 *
 * \param set [in] Set of JWT bundles object pointer.
 * \param bundle [in] JWT Bundle object pointer.
 * \param suc [out] <tt>true</tt> if there is a bundle for the given Trust
 * Domain, <tt>false</tt> otherwise. \returns The bundle for the given
 * Trust Domain if it exists, <tt>NULL</tt> otherwise.
 */
jwtbundle_Bundle *jwtbundle_Set_Get(jwtbundle_Set *s,
                                    const spiffeid_TrustDomain td, bool *suc);

/**
 * Gets the JWT bundles in the set.
 *
 * \param set [in] Set of JWT bundles object pointer.
 * \returns stb array of JWT bundle pointers. Each element must be freed
 * directly using jwtbundle_Bundle_Free, followed by the deallocation of
 * the array using arrfree.
 */
jwtbundle_Bundle **jwtbundle_Set_Bundles(jwtbundle_Set *s);

/**
 * Gets the size of set.
 *
 * \param set [in] Set of JWT bundles object pointer.
 * \returns The size of the set as an unsigned 32 bits integer.
 */
uint32_t jwtbundle_Set_Len(jwtbundle_Set *s);

/**
 * Prints bundle set to BIO object, including public keys.
 *
 * \param set [in] JWT Bundle Set object pointer to print.
 * \param offset [in] Integer. How many spaces to append before each line.
 * \param out [in] BIO object pointer.
 */
err_t jwtbundle_Set_print_BIO(jwtbundle_Set *set, int offset, BIO *out);

/**
 * Prints bundle set to file, including public keys.
 *
 * \param set [in] JWT Bundle Set object pointer to print.
 * \param offset [in] Integer. How many spaces to append before each line.
 * \param fd [in] file descriptor.
 */
err_t jwtbundle_Set_print_fd(jwtbundle_Set *set, int offset, FILE *fd);

/**
 * Prints bundle set to stdout, including public keys.
 *
 * \param bundle [in] JWT Bundle Set object pointer to print.
 * \param offset [in] Integer. How many spaces to append before each line.
 */
err_t jwtbundle_Set_print_stdout(jwtbundle_Set *b, int offset);

/**
 * Prints bundle set to stdout, including public keys.
 *
 * \param set [in] JWT Bundle Set object pointer to print.
 */
err_t jwtbundle_Set_Print(jwtbundle_Set *set);

/**
 * Gets bundle for a given Trust Domain object.
 *
 * \param set [in] Set of JWT bundles object pointer.
 * \param td [in] Trust Domain object.
 * \param err [out] Variable to get information in the event of error.
 * \returns The bundle for the given Trust Domain if it exists,
 * <tt>NULL</tt> otherwise.
 */
jwtbundle_Bundle *jwtbundle_Set_GetJWTBundleForTrustDomain(
    jwtbundle_Set *s, const spiffeid_TrustDomain td, err_t *err);

/**
 * Frees a set of JWT bundles object.
 *
 * \param set [in] Set of JWT bundles object pointer.
 */
void jwtbundle_Set_Free(jwtbundle_Set *s);

#ifdef __cplusplus
}
#endif

#endif
