#ifndef __INCLUDE_SVID_JWTSVID_SVID_H__
#define __INCLUDE_SVID_JWTSVID_SVID_H__

#include "../../../utils/src/util.h"
#include "../../../spiffeid/src/id.h"
#include <jansson.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct map_string_claim
{
    string_t key;
    json_t *value;
} map_string_claim;

typedef struct jwtsvid_SVID
{
    //its own spiffe id
    spiffeid_ID id;
    //stb array of audience
    string_t *audience;
    //expiration time
    time_t expiry;
    //claims map
    map_string_claim *claims;
    //token
    string_t token;
} jwtsvid_SVID;

jwtsvid_SVID* jwtsvid_ParseAndValidate();
jwtsvid_SVID* jwtsvid_ParseInsecure();
string_t jwtsvid_SVID_Marshal();
jwtsvid_SVID* jwtsvid_parse();
err_t jwtsvid_validateTokenAlgorithm();

#ifdef __cplusplus
}
#endif

#endif