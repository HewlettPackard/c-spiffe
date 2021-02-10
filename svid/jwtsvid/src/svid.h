#ifndef __INCLUDE_SVID_JWTSVID_SVID_H__
#define __INCLUDE_SVID_JWTSVID_SVID_H__

#include "../../../utils/src/util.h"
#include "../../../spiffeid/src/id.h"
#include "../../../bundle/jwtbundle/src/source.h"
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

typedef struct 
{
    json_t *header;
    json_t *payload;
    string_t header_str;
    string_t payload_str;
    string_t signature;
} jwtsvid_JWT;

typedef struct jwtsvid_SVID
{
    //its own spiffe id
    spiffeid_ID id;
    //stb array of audience
    string_arr_t audience;
    //expiration time
    time_t expiry;
    //claims map
    map_string_claim *claims;
    //token
    string_t token;
} jwtsvid_SVID;

typedef map_string_claim* (*token_validator_t)(jwtsvid_JWT*, 
                                            spiffeid_TrustDomain, 
                                            err_t*);

jwtsvid_SVID* jwtsvid_ParseAndValidate(char *token, 
                                        jwtbundle_Source *bundles,
                                        string_arr_t audience,
                                        err_t *err);
jwtsvid_SVID* jwtsvid_ParseInsecure(char *token, 
                                    string_arr_t audience, 
                                    err_t *err);
jwtsvid_SVID* jwtsvid_parse(char *token, 
                            string_arr_t audience, 
                            token_validator_t validator, 
                            err_t *err);
string_t jwtsvid_SVID_Marshal(jwtsvid_SVID *svid);
void jwtsvid_SVID_Free(jwtsvid_SVID *jwt);

#ifdef __cplusplus
}
#endif

#endif