#ifndef INCLUDE_SVID_JWTSVID_SVID_H
#define INCLUDE_SVID_JWTSVID_SVID_H

#include "bundle/jwtbundle/source.h"
#include "spiffeid/id.h"
#include "utils/util.h"
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

/** Validates the token and returns the claims. */
typedef map_string_claim *(*token_validator_t)(jwtsvid_JWT *,
                                               spiffeid_TrustDomain, void *,
                                               err_t *);

/**
 * Parses and validates a JWT-SVID token and returns the JWT-SVID. The
 * JWT-SVID signature is verified using the JWT bundle source.
 *
 * \param token [in] string JWT token.
 * \param bundles [in] Source of bundles.
 * \param audience [in] stb array of audiences.
 * \param err [out] Variable to get information in the event of error.
 * \returns Parsed JWT-SVID object pointer. Must be freed using
 * jwtsvid_SVID_Free function.
 */
jwtsvid_SVID *jwtsvid_ParseAndValidate(char *token, jwtbundle_Source *bundles,
                                       string_arr_t audience, err_t *err);

/**
 * Parses and validates a JWT-SVID token and returns the JWT-SVID. The
 * JWT-SVID signature is not verified.
 *
 * \param token [in] string JWT token.
 * \param audience [in] stb array of audiences.
 * \param err [out] Variable to get information in the event of error.
 * \returns Parsed JWT-SVID object pointer. Must be freed using
 * jwtsvid_SVID_Free function.
 */
jwtsvid_SVID *jwtsvid_ParseInsecure(char *token, string_arr_t audience,
                                    err_t *err);

/**
 * Parses and validates a JWT-SVID token and returns the JWT-SVID. The
 * validation step is defined by the validator function.
 *
 * \param token [in] string JWT token.
 * \param audience [in] stb array of audiences.
 * \param validator [in] Validator function.
 * \param arg [in] argument to pass to the validator.
 * \param err [out] Variable to get information in the event of error.
 * \returns Parsed JWT-SVID object pointer. Must be freed using
 * jwtsvid_SVID_Free function.
 */
jwtsvid_SVID *jwtsvid_parse(char *token, string_arr_t audience,
                            token_validator_t validator, void *arg,
                            err_t *err);

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
