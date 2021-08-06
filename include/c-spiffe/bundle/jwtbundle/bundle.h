#ifndef INCLUDE_BUNDLE_JWTBUNDLE_BUNDLE_H
#define INCLUDE_BUNDLE_JWTBUNDLE_BUNDLE_H

#include "c-spiffe/spiffeid/trustdomain.h"
#include <threads.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Bundle is a collection of trusted JWT authorities for a trust domain.
 */
typedef struct jwtbundle_Bundle {
    /** bundle trust domain */
    spiffeid_TrustDomain td;
    /** stb map of jwt authorities */
    map_string_EVP_PKEY *auths;
    /** mutex */
    mtx_t mtx;
} jwtbundle_Bundle;

/**
 * Creates a new bundle.
 *
 * \param td [in] Trust Domain object.
 * \returns New JWT Bundle object. Must be freed with jwtbundle_Bundle_Free
 * function.
 */
jwtbundle_Bundle *jwtbundle_New(const spiffeid_TrustDomain td);

/**
 * Creates a bundle from JWT certificates.
 *
 * \param td [in] Trust Domain object.
 * \param auths [in] stb map of public keys. Does not take ownership of the
 * object (it increases the ref count of the pointers instead). \returns
 * New JWT Bundle object. Must be freed with jwtbundle_Bundle_Free
 * function.
 */
jwtbundle_Bundle *jwtbundle_FromJWTAuthorities(const spiffeid_TrustDomain td,
                                               map_string_EVP_PKEY *auths);

/**
 * Loads a bundle from a file on disk.
 *
 * \param td [in] Trust Domain object.
 * \param path [in] path to file on disk.
 * \param err [out] Variable to get information in the event of error.
 * \returns New JWT Bundle object. Must be freed with jwtbundle_Bundle_Free
 * function.
 */
jwtbundle_Bundle *jwtbundle_Load(const spiffeid_TrustDomain td,
                                 const char *path, err_t *err);

/**
 * Decodes a bundle from bytes.
 *
 * \param td [in] Trust Domain object.
 * \param bundle_bytes [in] stb array of bytes in JWK format.
 * \returns New JWT Bundle object. Must be freed with jwtbundle_Bundle_Free
 * function.
 */
jwtbundle_Bundle *jwtbundle_Parse(const spiffeid_TrustDomain td,
                                  const char *bundle_bytes, err_t *err);

/**
 * Gets the Trust Domain that the bundle belongs to.
 *
 * \param bundle [in] JWT Bundle object pointer.
 * \returns Trust Domain object. Must NOT be modified of freed directly.
 * The object will be freed once the JWT Bundle object is freed.
 */
spiffeid_TrustDomain jwtbundle_Bundle_TrustDomain(const jwtbundle_Bundle *b);

/**
 * Gets the JWT authorities in the bundle.
 *
 * \param bundle [in] JWT Bundle object pointer.
 * \returns stb map of public key pointers. Each element must be freed
 * directly using EVP_PKEY_free, followed by the deallocation of the hash
 * map using shfree.
 */
map_string_EVP_PKEY *jwtbundle_Bundle_JWTAuthorities(jwtbundle_Bundle *b);

/**
 */
EVP_PKEY *jwtbundle_Bundle_FindJWTAuthority(jwtbundle_Bundle *bundle,
                                            const char *keyID, bool *suc);

/**
 * Checks if a JWT authority belongs to the bundle.
 *
 * \param bundle [in] JWT Bundle object pointer.
 * \param auth [in] JWT certificate pointer.
 * \returns <tt>true</tt> if the authority is a member of the bundle,
 * <tt>false</tt> otherwise.
 */
bool jwtbundle_Bundle_HasJWTAuthority(jwtbundle_Bundle *bundle,
                                      const char *keyID);

/**
 * Adds a JWT authority to the bundle. If the authority already exists
 * in the bundle, the contents of the bundle will remain unchanged.
 *
 * \param bundle [in] JWT Bundle object pointer.
 * \param auth [in] JWT certificate pointer.
 */
err_t jwtbundle_Bundle_AddJWTAuthority(jwtbundle_Bundle *bundle,
                                       const char *keyID, EVP_PKEY *pkey);

/**
 * Removes a JWT authority to the bundle. If the authority already does
 * not exist in the bundle, the contents of the bundle will remain
 * unchanged.
 *
 * \param bundle [in] JWT Bundle object pointer.
 * \param auth [in] JWT certificate pointer.
 */
void jwtbundle_Bundle_RemoveJWTAuthority(jwtbundle_Bundle *bundle,
                                         const char *keyID);

/**
 * Sets the JWT Authorities in the bundle.
 *
 * \param bundle [in] JWT Bundle object pointer.
 * \param stb array of JWT certificate pointers. The bundle does not take
 * ownership of auths, so it must be freed when it is no longer used.
 */
void jwtbundle_Bundle_SetJWTAuthorities(jwtbundle_Bundle *bundle,
                                        map_string_EVP_PKEY *auths);

/**
 * Checks if a bundle is empty JWT authority belongs to the bundle.
 *
 * \param bundle [in] JWT Bundle object pointer.
 * \returns <tt>true</tt> if the bundle is empty, <tt>false</tt> otherwise.
 */
bool jwtbundle_Bundle_Empty(jwtbundle_Bundle *b);

/**
 * Copies the content of a bundle.
 *
 * \param bundle [in] JWT Bundle object pointer.
 * \returns a copy of bundle. Must be freed using jwtbundle_Bundle_Free
 * function.
 */
jwtbundle_Bundle *jwtbundle_Bundle_Clone(jwtbundle_Bundle *b);

/**
 * Checks if a bundle is equal to another.
 *
 * \param bundle1 [in] JWT Bundle object pointer for first bundle.
 * \param bundle2 [in] JWT Bundle object pointer for second bundle.
 * \returns <tt>true</tt> if the bundle1 is equal to bundle2,
 * <tt>false</tt> otherwise.
 */
bool jwtbundle_Bundle_Equal(const jwtbundle_Bundle *b1,
                            const jwtbundle_Bundle *b2);

/**
 * Prints bundle to BIO object, including public keys.
 *
 * \param bundle [in] JWT Bundle object pointer to print.
 * \param offset [in] Integer. How many spaces to append before each line.
 * \param out [in] BIO object pointer. if provided, will be used but not freed.
 *  If not, a new one will be allocated and freed.
 */
err_t jwtbundle_Bundle_print_BIO(jwtbundle_Bundle *b, int offset, BIO *out);

/**
 * Prints bundle to file, including public keys.
 *
 * \param bundle [in] JWT Bundle object pointer to print.
 * \param offset [in] Integer. How many spaces to append before each line.
 * \param fd [in] file descriptor.
 */
err_t jwtbundle_Bundle_print_fd(jwtbundle_Bundle *b, int offset, FILE *fd);

/**
 * Prints bundle to stdout, including public keys.
 *
 * \param bundle [in] JWT Bundle object pointer to print.
 * \param offset [in] Integer. How many spaces to append before each line.
 */
err_t jwtbundle_Bundle_print_stdout(jwtbundle_Bundle *b, int offset);

/**
 * Prints bundle to stdout, including public keys.
 *
 * \param bundle [in] JWT Bundle object pointer to print.
 */
err_t jwtbundle_Bundle_Print(jwtbundle_Bundle *b);

/**
 * Gets bundle for a given Trust Domain object.
 *
 * \param bundle [in] JWT Bundle object pointer.
 * \param td [in] Trust Domain object.
 * \param err [out] Variable to get information in the event of error.
 * \returns bundle if the given Trust Domain is equal to the bundle's Trust
 * Domain, <tt>NULL</tt> otherwise.
 */
jwtbundle_Bundle *jwtbundle_Bundle_GetJWTBundleForTrustDomain(
    jwtbundle_Bundle *bundle, const spiffeid_TrustDomain td, err_t *err);

/**
 * Frees a JWT bundle object.
 *
 * \param bundle [in] A bundle object pointer to be deallocated.
 */
void jwtbundle_Bundle_Free(jwtbundle_Bundle *b);

#ifdef __cplusplus
}
#endif

#endif
