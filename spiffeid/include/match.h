#ifndef __INCLUDE_SPIFFE_MATCH_H__ 
#define __INCLUDE_SPIFFE_MATCH_H__

#include "id.h"
#include "../../utils/include/util.h"

enum enum_match_err_t
{
    MATCH_OK,
    MATCH_UNEXPECTED_ID,
    MATCH_UNEXPECTED_TD
};

typedef enum enum_match_err_t match_err_t;

typedef struct spiffeid_Matcher
{
    enum match_type {MATCH_ANY, MATCH_ONEOF, MATCH_MEMBEROF} type;
    spiffeid_ID *ids;
    spiffeid_TrustDomain td;
} spiffeid_Matcher;

match_err_t spiffeid_ApplyMatcher(const spiffeid_Matcher *matcher, const spiffeid_ID id);

spiffeid_Matcher* spiffeid_MatchAny();
spiffeid_Matcher* spiffeid_MatchID(const spiffeid_ID id);
spiffeid_Matcher* spiffeid_MatchOneOf(int n_args, ...);
spiffeid_Matcher* spiffeid_MatchMemberOf(const spiffeid_TrustDomain td);

#endif