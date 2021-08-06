#ifndef INCLUDE_BUNDLE_X509BUNDLE_SET_H
#define INCLUDE_BUNDLE_X509BUNDLE_SET_H

#include "c-spiffe/bundle/x509bundle/bundle.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    string_t key;
    x509bundle_Bundle *value;
} map_string_x509bundle_Bundle;

/** Set is a set of bundles, keyed by trust domain. */
typedef struct {
    /** map of bundles */
    map_string_x509bundle_Bundle *bundles;
    /** mutex */
    mtx_t mtx;
} x509bundle_Set;

/**
 * Creates a new set of X.509 bundles from a list of objects.
 *
 * \param n [in] The number of following arguments.
 * \param ... [in] List of n X.509 bundle object pointers.
 * \returns A set of X.509 bundles with the given objects.
 */
x509bundle_Set *x509bundle_NewSet(const int n_args, ...);

/**
 * Adds an X.509 bundle to the set. If the bundle already exists in the set
 * for the Trust Domain, the existing bundle is replaced.
 *
 * \param set [in] Set of X.509 bundles object pointer.
 * \param bundle [in] X.509 Bundle object pointer.
 */
void x509bundle_Set_Add(x509bundle_Set *set, x509bundle_Bundle *bundle);

/**
 * Removes an X.509 bundle to the set for the given Trust Domain.
 *
 * \param set [in] Set of X.509 bundles object pointer.
 * \param td [in] Trust Domain object.
 */
void x509bundle_Set_Remove(x509bundle_Set *set, const spiffeid_TrustDomain td);

/**
 * Checks if a bundle belongs to the set.
 *
 * \param set [in] Set of X.509 bundles object pointer.
 * \param td [in] Trust Domain object.
 * \returns <tt>true</tt> if there is a bundle for the given Trust Domain,
 * <tt>false</tt> otherwise.
 */
bool x509bundle_Set_Has(x509bundle_Set *set, const spiffeid_TrustDomain td);

/**
 * Gets an X.509 bundle from the set for a given Trust Domain.
 *
 * \param set [in] Set of X.509 bundles object pointer.
 * \param bundle [in] X.509 Bundle object pointer.
 * \param suc [out] <tt>true</tt> if there is a bundle for the given Trust
 * Domain, <tt>false</tt> otherwise. \returns The bundle for the given
 * Trust Domain if it exists, <tt>NULL</tt> otherwise.
 */
x509bundle_Bundle *x509bundle_Set_Get(x509bundle_Set *set,
                                      const spiffeid_TrustDomain td,
                                      bool *suc);

/**
 * Gets the X.509 bundles in the set.
 *
 * \param set [in] Set of X.509 bundles object pointer.
 * \returns stb array of X.509 bundle pointers. Each element must be freed
 * directly using x509bundle_Bundle_Free, followed by the deallocation of
 * the array using arrfree.
 */
x509bundle_Bundle **x509bundle_Set_Bundles(x509bundle_Set *set);

/**
 * Gets the size of set.
 *
 * \param set [in] Set of X.509 bundles object pointer.
 * \returns The size of the set as an unsigned 32 bits integer.
 */
uint32_t x509bundle_Set_Len(x509bundle_Set *set);

/**
 * Gets bundle for a given Trust Domain object.
 *
 * \param set [in] Set of X.509 bundles object pointer.
 * \param td [in] Trust Domain object.
 * \param err [out] Variable to get information in the event of error.
 * \returns The bundle for the given Trust Domain if it exists,
 * <tt>NULL</tt> otherwise.
 */
x509bundle_Bundle *x509bundle_Set_GetX509BundleForTrustDomain(
    x509bundle_Set *set, const spiffeid_TrustDomain td, err_t *err);

/**
 * Frees a set of X.509 bundles object.
 *
 * \param set [in] Set of X.509 bundles object pointer.
 */
void x509bundle_Set_Free(x509bundle_Set *set);

#ifdef __cplusplus
}
#endif

#endif
