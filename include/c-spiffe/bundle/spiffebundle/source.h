#ifndef INCLUDE_BUNDLE_SPIFFEBUNDLE_SOURCE_H
#define INCLUDE_BUNDLE_SPIFFEBUNDLE_SOURCE_H

#include "c-spiffe/bundle/spiffebundle/bundle.h"
#include "c-spiffe/bundle/spiffebundle/set.h"
#include "c-spiffe/federation/endpoint.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef struct spiffebundle_Endpoint spiffebundle_Endpoint;
/** Source represents a source of SPIFFE bundles keyed by trust domain. */
typedef struct spiffebundle_Source {
    enum spiffebundle_Source_Cardinality {
        SPIFFEBUNDLE_BUNDLE,
        SPIFFEBUNDLE_SET,
        SPIFFEBUNDLE_ENDPOINT
    } type;
    union {
        spiffebundle_Bundle *bundle;
        spiffebundle_Set *set;
        spiffebundle_Endpoint *endpoint;
    } source;
} spiffebundle_Source;

/**
 * Gets bundle for a given Trust Domain object.
 *
 * \param source [in] Source of SPIFFE bundles object pointer.
 * \param td [in] Trust Domain object.
 * \param err [out] Variable to get information in the event of error.
 * \returns The bundle for the given Trust Domain if it exists,
 * <tt>NULL</tt> otherwise.
 */
spiffebundle_Bundle *spiffebundle_Source_GetSpiffeBundleForTrustDomain(
    spiffebundle_Source *source, const spiffeid_TrustDomain td, err_t *err);

/**
 * Creates a source of SPIFFE bundles from a SPIFFE bundle. Takes ownership
 * of the object, so it will be freed when the source is freed.
 *
 * \param bundle [in] SPIFFE Bundle object pointer.
 * \returns A source of SPIFFE bundles object pointer.
 */
spiffebundle_Source *spiffebundle_SourceFromBundle(spiffebundle_Bundle *b);

/**
 * Creates a source of SPIFFE bundles from a set of SPIFFE bundles. Takes
 * ownership of the object, so it will be freed when the source is freed.
 *
 * \param set [in] Set of SPIFFE bundles object pointer.
 * \returns A source of SPIFFE bundles object pointer.
 */
spiffebundle_Source *spiffebundle_SourceFromSet(spiffebundle_Set *set);

/**
 * Creates a source of SPIFFE bundles from a workload API SPIFFE source of
 * bundles. Takes ownership of the object, so it will be freed when the source
 * is freed.
 *
 * \param source [in] SPIFFE BUNDLE Endpoint source of SPIFFE bundles object
 * pointer. \returns A source of SPIFFE bundles object pointer.
 */
spiffebundle_Source *
spiffebundle_SourceFromEndpoint(spiffebundle_Endpoint *endpoint);

/**
 * Frees a source of SPIFFE bundles object.
 *
 * \param source [in] source of SPIFFE bundles object pointer.
 */
void spiffebundle_Source_Free(spiffebundle_Source *source);

#ifdef __cplusplus
}
#endif

#endif
