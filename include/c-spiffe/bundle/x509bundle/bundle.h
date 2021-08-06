#ifndef INCLUDE_BUNDLE_X509BUNDLE_BUNDLE_H
#define INCLUDE_BUNDLE_X509BUNDLE_BUNDLE_H

#include "c-spiffe/spiffeid/trustdomain.h"
#include <openssl/x509.h>
#include <threads.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Bundle is a collection of trusted X.509 authorities for a trust domain.
 */
typedef struct {
    /** bundle trust domain */
    spiffeid_TrustDomain td;
    /** stb array of X.509 certificate pointers */
    X509 **auths;
    /** mutex */
    mtx_t mtx;
} x509bundle_Bundle;

/**
 * Creates a new bundle.
 *
 * \param td [in] Trust Domain object.
 * \returns New X.509 Bundle object. Must be freed with
 * x509bundle_Bundle_Free function.
 */
x509bundle_Bundle *x509bundle_New(const spiffeid_TrustDomain td);

/**
 * Creates a bundle from X.509 certificates.
 *
 * \param td [in] Trust Domain object.
 * \param auths [in] stb array of X.509 certificates. Does not take
 * ownership of the object (it increases the ref count of the pointers
 * instead). \returns New X.509 Bundle object. Must be freed with
 * x509bundle_Bundle_Free function.
 */
x509bundle_Bundle *
x509bundle_FromX509Authorities(const spiffeid_TrustDomain td, X509 **auths);

/**
 * Loads a bundle from a file on disk. The file must contain PEM-encoded
 * certificate blocks.
 *
 * \param td [in] Trust Domain object.
 * \param path [in] path to file on disk.
 * \param err [out] Variable to get information in the event of error.
 * \returns New X.509 Bundle object. Must be freed with
 * x509bundle_Bundle_Free function.
 */
x509bundle_Bundle *x509bundle_Load(const spiffeid_TrustDomain td,
                                   const char *path, err_t *err);

/**
 * Decodes a bundle from bytes. The contents must be PEM-encoded
 * certificate blocks.
 *
 * \param td [in] Trust Domain object.
 * \param bundle_bytes [in] stb array of PEM-encoded certificate blocks.
 * \returns New X.509 Bundle object. Must be freed with
 * x509bundle_Bundle_Free function.
 */
x509bundle_Bundle *x509bundle_Parse(const spiffeid_TrustDomain td,
                                    const char *bundle_bytes, err_t *err);

/**
 * Gets the Trust Domain that the bundle belongs to.
 *
 * \param bundle [in] X.509 Bundle object pointer.
 * \returns Trust Domain object. Must NOT be modified of freed directly.
 * The object will be freed once the X.509 Bundle object is freed.
 */
spiffeid_TrustDomain
x509bundle_Bundle_TrustDomain(const x509bundle_Bundle *bundle);

/**
 * Gets the X.509 authorities in the bundle.
 *
 * \param bundle [in] X.509 Bundle object pointer.
 * \returns stb array of X.509 certificate pointers. Each element must be
 * freed directly using X509_free, followed by the deallocation of the
 * array using arrfree.
 */
X509 **x509bundle_Bundle_X509Authorities(x509bundle_Bundle *bundle);

/**
 * Adds an X.509 authority to the bundle. If the authority already exists
 * in the bundle, the contents of the bundle will remain unchanged.
 *
 * \param bundle [in] X.509 Bundle object pointer.
 * \param auth [in] X.509 certificate pointer.
 */
void x509bundle_Bundle_AddX509Authority(x509bundle_Bundle *bundle, X509 *auth);

/**
 * Removes an X.509 authority to the bundle. If the authority already does
 * not exist in the bundle, the contents of the bundle will remain
 * unchanged.
 *
 * \param bundle [in] X.509 Bundle object pointer.
 * \param auth [in] X.509 certificate pointer.
 */
void x509bundle_Bundle_RemoveX509Authority(x509bundle_Bundle *bundle,
                                           X509 *auth);

/**
 * Checks if an X.509 authority belongs to the bundle.
 *
 * \param bundle [in] X.509 Bundle object pointer.
 * \param auth [in] X.509 certificate pointer.
 * \returns <tt>true</tt> if the authority is a member of the bundle,
 * <tt>false</tt> otherwise.
 */
bool x509bundle_Bundle_HasX509Authority(x509bundle_Bundle *bundle, X509 *auth);

/**
 * Sets the X.509 Authorities in the bundle.
 *
 * \param bundle [in] X.509 Bundle object pointer.
 * \param stb array of X.509 certificate pointers. The bundle does not take
 * ownership of auths, so it must be freed when it is no longer used.
 */
void x509bundle_Bundle_SetX509Authorities(x509bundle_Bundle *bundle,
                                          X509 **auths);

/**
 * Checks if a bundle is empty X.509 authority belongs to the bundle.
 *
 * \param bundle [in] X.509 Bundle object pointer.
 * \returns <tt>true</tt> if the bundle is empty, <tt>false</tt> otherwise.
 */
bool x509bundle_Bundle_Empty(x509bundle_Bundle *bundle);

/**
 * Checks if a bundle is equal to another.
 *
 * \param bundle1 [in] X.509 Bundle object pointer for first bundle.
 * \param bundle2 [in] X.509 Bundle object pointer for second bundle.
 * \returns <tt>true</tt> if the bundle1 is equal to bundle2,
 * <tt>false</tt> otherwise.
 */
bool x509bundle_Bundle_Equal(const x509bundle_Bundle *bundle1,
                             const x509bundle_Bundle *bundle2);

/**
 * Copies the content of a bundle.
 *
 * \param bundle [in] X.509 Bundle object pointer.
 * \returns a copy of bundle. Must be freed using x509bundle_Bundle_Free
 * function.
 */
x509bundle_Bundle *x509bundle_Bundle_Clone(x509bundle_Bundle *bundle);

/**
 * Gets bundle for a given Trust Domain object.
 *
 * \param bundle [in] X.509 Bundle object pointer.
 * \param td [in] Trust Domain object.
 * \param err [out] Variable to get information in the event of error.
 * \returns bundle if the given Trust Domain is equal to the bundle's Trust
 * Domain, <tt>NULL</tt> otherwise.
 */
x509bundle_Bundle *x509bundle_Bundle_GetX509BundleForTrustDomain(
    x509bundle_Bundle *bundle, const spiffeid_TrustDomain td, err_t *err);

/**
 * Frees a X.509 bundle object.
 *
 * \param bundle [in] A bundle object pointer to be deallocated.
 */
void x509bundle_Bundle_Free(x509bundle_Bundle *bundle);

#ifdef __cplusplus
}
#endif

#endif
