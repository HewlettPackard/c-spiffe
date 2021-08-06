#ifndef INCLUDE_BUNDLE_JWTBUNDLE_SOURCE_H
#define INCLUDE_BUNDLE_JWTBUNDLE_SOURCE_H

#include "c-spiffe/bundle/jwtbundle/bundle.h"
#include "c-spiffe/bundle/jwtbundle/set.h"
#include "c-spiffe/workload/jwtsource.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Source represents a source of JWT bundles keyed by trust domain. */
typedef struct {
    enum jwtbundle_Source_Cardinality {
        JWTBUNDLE_BUNDLE,
        JWTBUNDLE_SET,
        JWTBUNDLE_WORKLOADAPI_JWTSOURCE
    } type;
    union {
        jwtbundle_Bundle *bundle;
        jwtbundle_Set *set;
        workloadapi_JWTSource *source;
    } source;
} jwtbundle_Source;

/**
 * Gets bundle for a given Trust Domain object.
 *
 * \param source [in] Source of JWT bundles object pointer.
 * \param td [in] Trust Domain object.
 * \param err [out] Variable to get information in the event of error.
 * \returns The bundle for the given Trust Domain if it exists,
 * <tt>NULL</tt> otherwise.
 */
jwtbundle_Bundle *jwtbundle_Source_GetJWTBundleForTrustDomain(
    jwtbundle_Source *s, const spiffeid_TrustDomain td, err_t *err);

/**
 * Creates a source of JWT bundles from a JWT bundle. Takes ownership of
 * the object, so it will be freed when the source is freed.
 *
 * \param bundle [in] JWT Bundle object pointer.
 * \returns A source of JWT bundles object pointer.
 */
jwtbundle_Source *jwtbundle_SourceFromBundle(jwtbundle_Bundle *b);

/**
 * Creates a source of JWT bundles from a set of JWT bundles. Takes
 * ownership of the object, so it will be freed when the source is freed.
 *
 * \param set [in] Set of JWT bundles object pointer.
 * \returns A source of JWT bundles object pointer.
 */
jwtbundle_Source *jwtbundle_SourceFromSet(jwtbundle_Set *s);

/**
 * Creates a source of JWT bundles from a workload API JWT source of
 * bundles. Takes ownership of the object, so it will be freed when the source
 * is freed.
 *
 * \param set [in] Workload API source of JWT bundles object pointer.
 * \returns A source of JWT bundles object pointer.
 */
jwtbundle_Source *jwtbundle_SourceFromSource(workloadapi_JWTSource *s);

/**
 * Frees a source of JWT bundles object.
 *
 * \param source [in] source of JWT bundles object pointer.
 */
void jwtbundle_Source_Free(jwtbundle_Source *s);

#ifdef __cplusplus
}
#endif

#endif
