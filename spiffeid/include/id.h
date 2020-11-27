#ifndef __INCLUDE_SPIFFE_ID_H__ 
#define __INCLUDE_SPIFFE_ID_H__

#define __SPIFFE_ID_BY_POINTER__ 0

#include <stdbool.h>
#include "trustdomain.h"
#include "../../utils/include/util.h"

typedef spiffeid_ID struct
{
    spiffeid_TrustDomain td;
    //use stbds_arr or stb_sb for dynamic array allocation
    string_t path;
} spiffeid_ID;

spiffeid_ID spiffeid_ID_New(const string_t trustDomain, 
                            const string_arr_t segments, err_t *err);
string_t spiffeid_Join(string_t trustDomain, 
                            const string_arr_t segments, err_t *err);
spiffeid_ID spiffeid_ID_FromString(const string_t str, err_t *err);
spiffeid_ID spiffeid_ID_FromURI(const URL_t *uri, err_t *err);

#if __SPIFFE_ID_BY_POINTER__
spiffeid_TrustDomain spiffeid_ID_TrustDomain(const spiffeid_ID *id);
bool spiffeid_ID_MemberOf(const spiffeid_ID *id, const spiffeid_ID_TrustDomain *td);
const string_t spiffeid_ID_Path(const spiffeid_ID *id);
const string_t spiffeid_ID_String(const spiffeid_ID *id);
const URL_t spiffeid_ID_URL(const spiffeid_ID *id);
bool spiffeid_ID_IsZero(const spiffeid_ID *id);
#else
spiffeid_TrustDomain spiffeid_ID_TrustDomain(const spiffeid_ID id);
bool spiffeid_ID_MemberOf(const spiffeid_ID id, const spiffeid_ID_TrustDomain td);
const string_t spiffeid_ID_Path(const spiffeid_ID id);
const string_t spiffeid_ID_String(const spiffeid_ID id);
const URL_t spiffeid_ID_URL(const spiffeid_ID id);
bool spiffeid_ID_IsZero(const spiffeid_ID id);
#endif

void spiffeid_normalizeTrustDomain(string_t str);
string_t spiffeid_normalizePath(string_t str);

// void spiffeid_ID_Free(spiffeid_ID **id);
void spiffeid_ID_Free(spiffeid_ID *id, bool alloc);

/*
these functions below can panic (throw exception) on the original
Go implementation.

spiffeid_ID spiffeid_ID_Must(string_t trustDomain, string_arr_t segments);

string_t spiffeid_ID_MustJoin(string_t trustDomain, string_arr_t segments);

spiffeid_ID spiffeid_ID_RequireFromString(const string_t str);

spiffeid_ID spiffeid_ID_RequireFromURI(const URL_t str);
*/

#endif
