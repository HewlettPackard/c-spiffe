#ifndef __INCLUDE_SPIFFE_MATCH_H__ 
#define __INCLUDE_SPIFFE_MATCH_H__

#include "id.h"
#include "../../utils/include/util.h"

#if __SPIFFE_ID_BY_POINTER__
typedef err_t (*spiffeid_Matcher)(const spiffeid_ID*);
#else
typedef err_t (*spiffeid_Matcher)(const spiffeid_ID);
#endif

spiffeid_Matcher spiffeid_MatchAny();

#if __SPIFFE_ID_BY_POINTER__
spiffeid_Matcher spiffeid_MatchID(const spiffeid_ID *id);

#else
spiffeid_Matcher spiffeid_MatchID(const spiffeid_ID id);
//spiffeid_Matcher spiffeid_MatchOneOf(const spiffeid_ID id_arr, ...);
#endif

spiffeid_Matcher spiffeid_MatchOneOf(const spiffeid_ID *id_arr);

#if __TRUSTDOMAIN_BY_POINTER__
spiffeid_Matcher spiffeid_MatchMemberOf(const spiffeid_TrustDomain *td,);
#else
spiffeid_Matcher spiffeid_MatchMemberOf(const spiffeid_TrustDomain td);
#endif

#endif