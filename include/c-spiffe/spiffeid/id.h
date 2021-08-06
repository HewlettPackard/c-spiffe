#ifndef INCLUDE_SPIFFEID_ID_H
#define INCLUDE_SPIFFEID_ID_H

#include "c-spiffe/utils/util.h"
#include <stdbool.h>
#include <uriparser/Uri.h>

#ifdef __cplusplus
extern "C" {
#endif

/** An instance of a Trust Domain object. */
typedef struct {
    /** stb string for the name of the Trust Domain. */
    string_t name;
} spiffeid_TrustDomain;

/** An instance of a SPIFFE ID object. */
typedef struct {
    /** Trust Domain object of the SPIFFE ID */
    spiffeid_TrustDomain td;
    /** stb string for the path of the SPIFFE ID */
    string_t path;
} spiffeid_ID;

/**
 * Creates a path from the segments in the string array.
 *
 * \param str_arr [in] A stb array of stb strings composed of segments. Its
 * elements may be modified. \returns (new reference) Path created from the
 * segments. Must be freed using arrfree function.
 */
string_t join(string_arr_t str_arr);

/**
 * Creates a SPIFFE ID object from trust domain and segments.
 *
 * \param td_str [in] A stb string for the Trust Domain name.
 * \param segments [in] A stb array of stb strings of segments for the
 * path.
 * \param err [out] Variable to get information in the event of
 * error.
 * \returns A new SPIFFE ID object constructed from the parameters.
 * The fields are NULL in case of error. Must be freed using
 * spiffeid_ID_Free function.
 */
spiffeid_ID spiffeid_ID_New(const char *td_str, const string_arr_t segments,
                            err_t *err);

/**
 * Creates a SPIFFE ID string from trust domain and segments.
 *
 * \param td_str [in] A stb string for the Trust Domain name.
 * \param segments [in] A stb array of stb strings of segments for the
 * path.
 * \param err [out] Variable to get information in the event of
 * error.
 * \returns A new SPIFFE ID string constructed from the parameters.
 * The fields are NULL in case of error. Must be freed using arrfree
 * function.
 */
string_t spiffeid_Join(const char *td_str, const string_arr_t segments,
                       err_t *err);

/**
 * Creates a SPIFFE ID object from a SPIFFE ID string representation;
 *
 * \param str [in] A SPIFFE ID string.
 * \param err [out] Variable to get information in the event of error.
 * \returns A new SPIFFE ID string constructed from the parameters. The
 * fields are NULL in case of error. Must be freed using spiffeid_ID_Free
 * function.
 */
spiffeid_ID spiffeid_FromString(const char *str, err_t *err);

/**
 * Creates a SPIFFE ID object from a URI object.
 *
 * \param uri [in] An URI object.
 * \param err [out] Variable to get information in the event of error.
 * \returns A new SPIFFE ID string constructed from the parameters. The
 * fields are NULL in case of error. Must be freed using spiffeid_ID_Free
 * function.
 */
spiffeid_ID spiffeid_FromURI(const UriUriA *uri, err_t *err);

/**
 * Gets a Trust Domain object from a SPIFFE ID object.
 *
 * \param id [in] A SPIFFE ID object.
 * \returns A Trust Domain object of the SPIFFE ID. Must NOT be modified or
 * freed directly. The object will be freed once the SPIFFE ID object is
 * freed.
 */
spiffeid_TrustDomain spiffeid_ID_TrustDomain(const spiffeid_ID id);

/**
 * Checks whether a SPIFFE ID is member of a given Trust Domain.
 *
 * \param id A SPIFFE ID object.
 * \param td A Trust Domain object.
 * \returns <tt>true</tt> if the ID is a member of the Trust Domain.
 * <tt>false</tt> otherwise.
 */
bool spiffeid_ID_MemberOf(const spiffeid_ID id, const spiffeid_TrustDomain td);

/**
 * Gets the path from a SPIFFE ID object.
 *
 * \param id [in] A SPIFFE ID object.
 * \returns A stb string for the path. Must NOT be modified or freed
 * directly. The string will be freed once the SPIFFE ID object is freed.
 */
const char *spiffeid_ID_Path(const spiffeid_ID id);

/**
 * Gets a string representation of a SPIFFE ID object.
 *
 * \param id [in] A SPIFFE ID object.
 * \returns A stb string for the representation. Must be freed using
 * arrfree function.
 */
string_t spiffeid_ID_String(const spiffeid_ID id);

/**
 * Check whether a SPIFFE ID object is zero value.
 *
 * \param id [in] A SPIFFE ID object.
 * \returns <tt>true</tt> if the object is zero, <tt>false</tt> otherwise.
 */
bool spiffeid_ID_IsZero(const spiffeid_ID id);

string_t spiffeid_normalizeTrustDomain(string_t str);
string_t spiffeid_normalizePath(string_t str);

/**
 * Frees a SPIFFE ID object.
 *
 * \param id [in] A SPIFFE ID object pointer to be deallocated.
 */
void spiffeid_ID_Free(spiffeid_ID *id);

#ifdef __cplusplus
}
#endif

#endif
