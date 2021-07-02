#ifndef INCLUDE_SPIFFEID_TRUSTDOMAIN_H
#define INCLUDE_SPIFFEID_TRUSTDOMAIN_H

#include "c-spiffe/spiffeid/id.h"
#include "c-spiffe/utils/util.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Gets a Trust Domain object from a string. The string can either be the
 * host part of a URI authority component (e.g. example.org), or a valid
 * SPIFFE ID URI (e.g. spiffe://example.org), otherwise an error is
 * returned.
 *
 * \param str [in] A C string with the Trust Domain representation.
 * \param err [out] Variable to get information in the event of error.
 * \returns A Trust Domain object constructed with the parameter.
 */
spiffeid_TrustDomain spiffeid_TrustDomainFromString(const char *str,
                                                    err_t *err);

/**
 * Gets a Trust Domain object from an URI object. The URI must be a valid
 * SPIFFE ID or an error is returned. The trust domain is extracted from
 * the host field and normalized to lower case.
 *
 * \param str [in] An URI object with the Trust Domain representation.
 * \param err [out] Variable to get information in the event of error.
 * \returns A Trust Domain object constructed with the parameter.
 */
spiffeid_TrustDomain spiffeid_TrustDomainFromURI(const UriUriA *uri,
                                                 err_t *err);

/**
 * Gets the string representation of a Trust Domain object.
 *
 * \param td [in] A Trust Domain object.
 * \returns A stb string for the representation. Must NOT be modified of
 * freed directly. The string will be freed once the Trust Domain object is
 * freed.
 */
const char *spiffeid_TrustDomain_String(const spiffeid_TrustDomain td);

/**
 * Gets the SPIFFE ID object of a Trust Domain.
 *
 * \param td [in] A Trust Domain object.
 * \returns A SPIFFE ID object for the Trust Domain object. Must be freed
 * using spiffeid_ID_Free function.
 */
spiffeid_ID spiffeid_TrustDomain_ID(const spiffeid_TrustDomain td);

/**
 * Gets a string representation of the SPIFFE ID of the trust domain.
 *
 * \param td [in] A Trust Domain object.
 * \returns A std string with the SPIFFE ID representation. Must be freed
 * using arrfree function.
 */
string_t spiffeid_TrustDomain_IDString(const spiffeid_TrustDomain td);

/**
 * Gets a SPIFFE ID with the given path inside the trust domain.
 *
 * \param td [in] A Trust Domain object.
 * \param path [in] stb string with the path.
 * \returns A SPIFFE ID object for the Trust Domain and path. Must be freed
 * using spiffeid_ID_Free function.
 */
spiffeid_ID spiffeid_TrustDomain_NewID(const spiffeid_TrustDomain td,
                                       const char *path);

/**
 * Checks whether Trust Domain object has empty fields.
 *
 * \param td [in] A Trust Domain object.
 * \returns <tt>true</tt> if the name field is zero, <tt>false</tt>
 * otherwise.
 */
bool spiffeid_TrustDomain_IsZero(const spiffeid_TrustDomain td);

/**
 * Compare returns an integer comparing the trust domain to another
 * lexicographically.
 *
 * \param td1 [in] Dirst Trust Domain object to compare.
 * \param td2 [in] Second Trust Domain object to compare.
 * \returns 0 if td1 == td2, a negative value if td1 < td2 and a positive
 * value ig td1 > td2.
 */
int spiffeid_TrustDomain_Compare(const spiffeid_TrustDomain td1,
                                 const spiffeid_TrustDomain td2);

/**
 * Frees a Trust Domain object.
 *
 * \param td [in] A Trust Domain pointer to be deallocated.
 */
void spiffeid_TrustDomain_Free(spiffeid_TrustDomain *td);

#ifdef __cplusplus
}
#endif

#endif
