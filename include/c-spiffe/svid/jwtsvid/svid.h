#ifndef INCLUDE_SVID_JWTSVID_SVID_H
#define INCLUDE_SVID_JWTSVID_SVID_H

#include "c-spiffe/spiffeid/id.h"
#include "c-spiffe/utils/util.h"
#include <jansson.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct map_string_claim {
    string_t key;
    json_t *value;
} map_string_claim;

/** JWT object */
typedef struct {
    /** header in json internal format */
    json_t *header;
    /** payload in json internal format */
    json_t *payload;
    /** header in stb string Base64URL encoding */
    string_t header_str;
    /** payload in stb string Base64URL encoding */
    string_t payload_str;
    /** signature in stb string Base64URL encoding */
    string_t signature;
} jwtsvid_JWT;

/** JWT parameters */
typedef struct jwtsvid_Params {
    string_t audience;
    string_arr_t extra_audiences;
    spiffeid_ID subject;
} jwtsvid_Params;

/** JWT-SVID object */
typedef struct jwtsvid_SVID {
    /** The SPIFFE ID of the JWT-SVID as present in the 'sub' claim */
    spiffeid_ID id;
    /** stb array of audience, intended recipients of JWT-SVID as present
     * in the 'aud' claim */
    string_arr_t audience;
    /** The expiration time of JWT-SVID as present in 'exp' claim */
    time_t expiry;
    /** The parsed claims from token */
    map_string_claim *claims;
    /** Serialized JWT token */
    string_t token;
} jwtsvid_SVID;

/**
 * Marshal returns the JWT-SVID marshaled to a string.
 *
 * \param svid [in] JWT-SVID object pointer.
 * \returns string with JWT token value. It must NOT be altered or freed
 * directly.
 */
const char *jwtsvid_SVID_Marshal(jwtsvid_SVID *svid);

/**
 * Frees a JWT-SVID object.
 *
 * \param svid [in] JWT-SVID object pointer.
 */
void jwtsvid_SVID_Free(jwtsvid_SVID *svid);

#ifdef __cplusplus
}
#endif

#endif
