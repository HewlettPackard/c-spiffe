#ifndef __INCLUDE_SPIFFEID_MATCH_H__ 
#define __INCLUDE_SPIFFEID_MATCH_H__

#include "id.h"
#include "../../utils/src/util.h"

enum enum_match_err_t
{
    MATCH_OK,
    MATCH_UNEXPECTED_ID,
    MATCH_UNEXPECTED_TD
};
typedef enum enum_match_err_t match_err_t;

enum enum_match_t
{
    MATCH_ANY, 
    MATCH_ONEOF, 
    MATCH_MEMBEROF
};

typedef enum enum_match_t match_t;

typedef struct spiffeid_Matcher
{
    match_t type;
    spiffeid_ID *ids;
    spiffeid_TrustDomain td;
} spiffeid_Matcher;

match_err_t spiffeid_ApplyMatcher(const spiffeid_Matcher *matcher, const spiffeid_ID id);

spiffeid_Matcher* spiffeid_MatchAny(void);
spiffeid_Matcher* spiffeid_MatchID(const spiffeid_ID id);
spiffeid_Matcher* spiffeid_MatchOneOf(int n_args, ...);
spiffeid_Matcher* spiffeid_vMatchOneOf(int n_args, va_list args);
spiffeid_Matcher* spiffeid_MatchMemberOf(const spiffeid_TrustDomain td);

void spiffeid_Matcher_Free(spiffeid_Matcher *matcher);

#endif