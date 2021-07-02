#ifndef INCLUDE_SVID_JWTSVID_PARSE_H
#define INCLUDE_SVID_JWTSVID_PARSE_H

#include "c-spiffe/bundle/jwtbundle/source.h"
#include "c-spiffe/svid/jwtsvid/svid.h"

#ifdef __cplusplus
extern "C" {
#endif

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

#ifdef __cplusplus
}
#endif

#endif
