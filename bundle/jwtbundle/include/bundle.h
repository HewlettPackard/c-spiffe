#ifndef __INCLUDE_JWTBUNDLE_BUNDLE_H__
#define __INCLUDE_JWTBUNDLE_BUNDLE_H__

#include <threads.h>
#include "../../../internal/jwtutil/include/util.h"
#include "../../../spiffeid/include/id.h"

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
                                            const map_string_EVP_PKEY *auths);
jwtbundle_Bundle* jwtbundle_Load(const spiffeid_TrustDomain td, 
                                            const string_t path, 
                                            err_t *err);
jwtbundle_Bundle* jwtbundle_Read(const spiffeid_TrustDomain td, 
                                            void *reader,   //Fix 
                                            err_t *err);
jwtbundle_Bundle* jwtbundle_Parse(const spiffeid_TrustDomain td, 
                                            const byte *bbytes, 
                                            err_t *err);
                                            
spiffeid_TrustDomain jwtbundle_Bundle_TrustDomain(const jwtbundle_Bundle *b);
map_string_EVP_PKEY* jwtbundle_Bundle_JWTAuthorities(const jwtbundle_Bundle *b);
EVP_PKEY* jwtbundle_Bundle_FindJWTAuthority(const jwtbundle_Bundle *b,
                                            const string_t keyID, 
                                            bool *suc);
bool jwtbundle_Bundle_HasJWTAuthority(const jwtbundle_Bundle *b, 
                                        const string_t keyID);
err_t jwtbundle_Bundle_AddJWTAuthority(jwtbundle_Bundle *b,
                                        const string_t keyID,
                                        const EVP_PKEY *pkey);
void jwtbundle_Bundle_RemoveJWTAuthority(jwtbundle_Bundle *b, 
                                            const string_t keyID);
void jwtbundle_Bundle_SetJWTAuthorities(jwtbundle_Bundle *b,
                                        const map_string_EVP_PKEY *auths);
bool jwtbundle_Bundle_Empty(const jwtbundle_Bundle *b);
byte* jwtbundle_Bundle_Marshal(const jwtbundle_Bundle *b, err_t *err);
jwtbundle_Bundle* jwtbundle_Bundle_Clone(const jwtbundle_Bundle *b);
bool jwtbundle_Bundle_Equal(const jwtbundle_Bundle *b1, 
                            const jwtbundle_Bundle *b2);
jwtbundle_Bundle* jwtbundle_Bundle_GetJWTBundleForTrustDomain(
                                            const jwtbundle_Bundle *b,
                                            const spiffeid_TrustDomain td,
                                            err_t *err);

#endif