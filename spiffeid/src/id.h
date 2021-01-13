#ifndef __INCLUDE_SPIFFEID_ID_H__ 
#define __INCLUDE_SPIFFEID_ID_H__

#define __SPIFFE_ID_BY_POINTER__ 0

#include <stdbool.h>
#include <uriparser/Uri.h>
// #include <curl/curl.h>
#include "../../utils/src/util.h"

typedef struct spiffeid_TrustDomain
{
    string_t name;
} spiffeid_TrustDomain;

typedef struct spiffeid_ID
{
    spiffeid_TrustDomain td;
    //use stbds_arr or stb_sb for dynamic array allocation
    string_t path;
} spiffeid_ID;

string_t join(string_arr_t str_arr);

spiffeid_ID spiffeid_ID_New(string_t td_str, 
                            const string_arr_t segments, err_t *err);
string_t spiffeid_Join(string_t td_str, 
                        const string_arr_t segments, err_t *err);
spiffeid_ID spiffeid_FromString(const string_t str, err_t *err);
spiffeid_ID spiffeid_FromURI(const UriUriA *uri, err_t *err);

#if __SPIFFE_ID_BY_POINTER__
spiffeid_TrustDomain spiffeid_ID_TrustDomain(const spiffeid_ID *id);
bool spiffeid_ID_MemberOf(const spiffeid_ID *id, const spiffeid_ID_TrustDomain *td);
const string_t spiffeid_ID_Path(const spiffeid_ID *id);
string_t spiffeid_ID_String(const spiffeid_ID *id);
CURLU* spiffeid_ID_URL(const spiffeid_ID *id);
bool spiffeid_ID_IsZero(const spiffeid_ID *id);
#else
spiffeid_TrustDomain spiffeid_ID_TrustDomain(const spiffeid_ID id);
bool spiffeid_ID_MemberOf(const spiffeid_ID id, const spiffeid_TrustDomain td);
const string_t spiffeid_ID_Path(const spiffeid_ID id);
string_t spiffeid_ID_String(const spiffeid_ID id);
// UriUriA spiffeid_ID_URI(const spiffeid_ID id);
bool spiffeid_ID_IsZero(const spiffeid_ID id);
#endif

string_t spiffeid_normalizeTrustDomain(string_t str);
string_t spiffeid_normalizePath(string_t str);

// void spiffeid_ID_Free(spiffeid_ID **id);
void spiffeid_ID_Free(spiffeid_ID *id, bool alloc);

/*
these functions below can panic (throw exception) on the original
Go implementation.

spiffeid_ID spiffeid_ID_Must(string_t trustDomain, string_arr_t segments);

string_t spiffeid_ID_MustJoin(string_t trustDomain, string_arr_t segments);

spiffeid_ID spiffeid_ID_RequireFromString(const string_t str);

spiffeid_ID spiffeid_ID_RequireFromURI(const CURLU str);
*/

#endif
