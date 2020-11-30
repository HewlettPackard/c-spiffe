#ifndef __INCLUDE_SPIFFE_TRUSTDOMAIN_H__ 
#define __INCLUDE_SPIFFE_TRUSTDOMAIN_H__

#define __TRUSTDOMAIN_BY_POINTER__ 0

#include "id.h"
#include "../../utils/include/util.h"

typedef struct spiffeid_TrustDomain
{
    string_t name;
} spiffeid_TrustDomain;

spiffeid_TrustDomain spiffeid_TrustDomainFromString(const string_t str, err_t *err);
spiffeid_TrustDomain spiffeid_TrustDomainFromURI(const CURL *uri, err_t *err);

#if __TRUSTDOMAIN_BY_POINTER__
const string_t spiffeid_TrustDomain_String(const spiffeid_TrustDomain *td);
spiffeid_ID spiffeid_TrustDomain_ID(const spiffeid_TrustDomain *td);
string_t spiffeid_TrustDomain_IDString(const spiffeid_TrustDomain *td);
spiffeid_ID spiffeid_TrustDomain_NewID(const spiffeid_TrustDomain *td, const string_t str);
bool spiffeid_ID_IsZero(const spiffeid_TrustDomain *td);
int spiffeid_ID_Compare(const spiffeid_TrustDomain *td);
#else
const string_t spiffeid_TrustDomain_String(const spiffeid_TrustDomain td);
spiffeid_ID spiffeid_TrustDomain_ID(const spiffeid_TrustDomain td);
string_t spiffeid_TrustDomain_IDString(const spiffeid_TrustDomain td);
spiffeid_ID spiffeid_TrustDomain_NewID(const spiffeid_TrustDomain td, const string_t path);
bool spiffeid_TrustDomain_IsZero(const spiffeid_TrustDomain td);
int spiffeid_TrustDomain_Compare(const spiffeid_TrustDomain td1, const spiffeid_TrustDomain td2);
#endif

// void spiffeid_TrustDomain_Free(spiffeid_TrustDomain **tdptr);
void spiffeid_TrustDomain_Free(spiffeid_TrustDomain *td, bool alloc);

/*
these functions below can panic (throw exception) on the original
Go implementation.

spiffeid_TrustDomain spiffeid_RequireTrustDomainFromString(const string_t str);

spiffeid_TrustDomain spiffeid_RequireTrustDomainFromURI(const URI_t uri);
*/

#endif