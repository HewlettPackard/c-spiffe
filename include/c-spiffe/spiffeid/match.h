#ifndef INCLUDE_SPIFFEID_MATCH_H
#define INCLUDE_SPIFFEID_MATCH_H

#include "c-spiffe/utils/util.h"
#include "c-spiffe/spiffeid/id.h"

#ifdef __cplusplus
extern "C" {
#endif

enum enum_match_err_t { MATCH_OK, MATCH_UNEXPECTED_ID, MATCH_UNEXPECTED_TD };
typedef enum enum_match_err_t match_err_t;

enum enum_match_t { MATCH_ANY, MATCH_ONEOF, MATCH_MEMBEROF };
typedef enum enum_match_t match_t;

/** Matcher object */
typedef struct {
    /** Type to match (matches any, bunch of ids or trust domain) */
    match_t type;
    /** stb array of SPIFFE ID objects. Used in case type is MATCH_ONEOF */
    spiffeid_ID *ids;
    /** Trust Domain object. Used in case type is MATCH_MEMBEROF */
    spiffeid_TrustDomain td;
} spiffeid_Matcher;

/**
 * Apply a given matcher to a given spiffe ID.
 *
 * \param matcher [in] Pointer to Matcher object.
 * \param id [in] spiffe ID object.
 * \returns MATCH_OK if it matches, MATCH_UNEXPECTED_ID if id does not
 * match any of the IDs in the matcher or MATCH_UNEXPECTED_TD if id does
 * not match the Trust Domain in the matcher.
 */
match_err_t spiffeid_ApplyMatcher(const spiffeid_Matcher *matcher,
                                  const spiffeid_ID id);

/**
 *
 * \returns A matcher that matches any ID.
 */
spiffeid_Matcher *spiffeid_MatchAny(void);

/**
 * \param id [in] A spiffe ID object.
 * \returns A matcher that matches a given ID.
 */
spiffeid_Matcher *spiffeid_MatchID(const spiffeid_ID id);

/**
 * \param n [in] The number of following arguments.
 * \param ... [in] List of n spiffe ID objects.
 * \returns A matcher that matches any ID from a list.
 */
spiffeid_Matcher *spiffeid_MatchOneOf(int n_args, ...);

/**
 * \param n [in] The size of the va_list.
 * \param args [in] va_list of n spiffe ID objects.
 * \returns A matcher that matches any ID from a va_list.
 */
spiffeid_Matcher *spiffeid_vMatchOneOf(int n_args, va_list args);

/**
 * \param td [in] Trust Domain object.
 * \returns A matcher that matches any ID member of a given Trust Domain.
 */
spiffeid_Matcher *spiffeid_MatchMemberOf(const spiffeid_TrustDomain td);

/**
 * Frees a Matcher object.
 * \param matcher [in] Matcher pointer to be deallocated.
 */
void spiffeid_Matcher_Free(spiffeid_Matcher *matcher);

#ifdef __cplusplus
}
#endif

#endif
