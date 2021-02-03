#ifndef __INCLUDE_BUNDLE_JWTBUNDLE_BUNDLE_H__
#define __INCLUDE_BUNDLE_JWTBUNDLE_BUNDLE_H__

#include <threads.h>
#include "../../../spiffeid/src/id.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct jwtbundle_Bundle
{
    //bundle trust domain
    spiffeid_TrustDomain td;
    //map of jwt authorities
    map_string_EVP_PKEY *auths;
    //lock
    mtx_t mtx;
} jwtbundle_Bundle;

jwtbundle_Bundle* jwtbundle_New(const spiffeid_TrustDomain td);
jwtbundle_Bundle* jwtbundle_FromJWTAuthorities(const spiffeid_TrustDomain td,
                                                map_string_EVP_PKEY *auths);
jwtbundle_Bundle* jwtbundle_Load(const spiffeid_TrustDomain td, 
                                    const char *path, 
                                    err_t *err);
jwtbundle_Bundle* jwtbundle_Parse(const spiffeid_TrustDomain td, 
                                    const string_t bbytes, 
                                    err_t *err);

spiffeid_TrustDomain jwtbundle_Bundle_TrustDomain(const jwtbundle_Bundle *b);
map_string_EVP_PKEY* jwtbundle_Bundle_JWTAuthorities(jwtbundle_Bundle *b);
EVP_PKEY* jwtbundle_Bundle_FindJWTAuthority(jwtbundle_Bundle *b,
                                            const char *keyID, 
                                            bool *suc);
bool jwtbundle_Bundle_HasJWTAuthority(jwtbundle_Bundle *b, 
                                        const char *keyID);
err_t jwtbundle_Bundle_AddJWTAuthority(jwtbundle_Bundle *b,
                                        const char *keyID,
                                        EVP_PKEY *pkey);
void jwtbundle_Bundle_RemoveJWTAuthority(jwtbundle_Bundle *b, 
                                            const char *keyID);
void jwtbundle_Bundle_SetJWTAuthorities(jwtbundle_Bundle *b,
                                        map_string_EVP_PKEY *auths);
bool jwtbundle_Bundle_Empty(jwtbundle_Bundle *b);
jwtbundle_Bundle* jwtbundle_Bundle_Clone(jwtbundle_Bundle *b);
bool jwtbundle_Bundle_Equal(const jwtbundle_Bundle *b1, 
                            const jwtbundle_Bundle *b2);
jwtbundle_Bundle* jwtbundle_Bundle_GetJWTBundleForTrustDomain(
                                            jwtbundle_Bundle *b,
                                            const spiffeid_TrustDomain td,
                                            err_t *err);
void jwtbundle_Bundle_Free(jwtbundle_Bundle *b, bool alloc);

#ifdef __cplusplus
}
#endif

#endif
