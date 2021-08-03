/**

(C) Copyright 2020-2021 Hewlett Packard Enterprise Development LP

 

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

 

    http://www.apache.org/licenses/LICENSE-2.0

 

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.

**/

#ifndef INCLUDE_BUNDLE_X509BUNDLE_SOURCE_H
#define INCLUDE_BUNDLE_X509BUNDLE_SOURCE_H

#include "c-spiffe/bundle/x509bundle/bundle.h"
#include "c-spiffe/bundle/x509bundle/set.h"
#include "c-spiffe/workload/x509source.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Source represents a source of X.509 bundles keyed by trust domain. */
typedef struct {
    enum x509bundle_Source_Cardinality {
        X509BUNDLE_BUNDLE,
        X509BUNDLE_SET,
        X509BUNDLE_WORKLOADAPI_X509SOURCE
    } type;
    union {
        x509bundle_Bundle *bundle;
        x509bundle_Set *set;
        workloadapi_X509Source *source;
    } source;
} x509bundle_Source;

/**
 * Gets bundle for a given Trust Domain object.
 *
 * \param source [in] Source of X.509 bundles object pointer.
 * \param td [in] Trust Domain object.
 * \param err [out] Variable to get information in the event of error.
 * \returns The bundle for the given Trust Domain if it exists,
 * <tt>NULL</tt> otherwise.
 */
x509bundle_Bundle *x509bundle_Source_GetX509BundleForTrustDomain(
    x509bundle_Source *source, const spiffeid_TrustDomain td, err_t *err);

/**
 * Creates a source of X.509 bundles from a X.509 bundle. Takes ownership
 * of the object, so it will be freed when the source is freed.
 *
 * \param bundle [in] X.509 Bundle object pointer.
 * \returns A source of X.509 bundles object pointer.
 */
x509bundle_Source *x509bundle_SourceFromBundle(x509bundle_Bundle *b);

/**
 * Creates a source of X.509 bundles from a set of X.509 bundles. Takes
 * ownership of the object, so it will be freed when the source is freed.
 *
 * \param set [in] Set of X.509 bundles object pointer.
 * \returns A source of X.509 bundles object pointer.
 */
x509bundle_Source *x509bundle_SourceFromSet(x509bundle_Set *set);

/**
 * Creates a source of X.509 bundles from a workload API X.509 source of
 * bundles. Takes ownership of the object, so it will be freed when the source
 * is freed.
 *
 * \param source [in] Workload API source of X.509 bundles object pointer.
 * \returns A source of X.509 bundles object pointer.
 */
x509bundle_Source *x509bundle_SourceFromSource(workloadapi_X509Source *source);

/**
 * Frees a source of X.509 bundles object.
 *
 * \param source [in] source of X.509 bundles object pointer.
 */
void x509bundle_Source_Free(x509bundle_Source *source);

#ifdef __cplusplus
}
#endif

#endif
