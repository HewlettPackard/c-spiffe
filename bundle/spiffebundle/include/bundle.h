#ifndef __INCLUDE_BUNDLE_SPIFFEBUNDLE_BUNDLE_H__
#define __INCLUDE_BUNDLE_SPIFFEBUNDLE_BUNDLE_H__

#include <time.h>
#include <threads.h>
#include <openssl/x509.h>
#include "../../jwtbundle/include/bundle.h"
#include "../../x509bundle/include/bundle.h"
#include "../../../spiffeid/include/trustdomain.h"
#include "../../../utils/src/util.h"

typedef struct spiffebundle_Bundle
{
    //bundle trust domain
    spiffeid_TrustDomain td;
    ///TODO: implement a RW mutex instead
    //read write mutex
    mtx_t mtx;
    //time duration (...)
    struct timespec *refreshHint;
    //sequence number
    uint64_t *seqNumber;
    //hash of jwt authorities
    map_string_EVP_PKEY *jwtAuths;
    //STB array of x509 certificates
    X509 **x509Auths;
} spiffebundle_Bundle;

spiffebundle_Bundle* spiffebundle_New(const spiffeid_TrustDomain td);
spiffebundle_Bundle* spiffebundle_Load(const spiffeid_TrustDomain td, 
                                        const string_t path, 
                                        err_t *err);
// spiffebundle_Bundle* spiffebundle_Read(const spiffeid_TrustDomain td,
//                                         void *reader,
//                                         err_t *err);
spiffebundle_Bundle* spiffebundle_Parse(const spiffeid_TrustDomain td,
                                        const byte *bundleBytes,
                                        err_t *err);
spiffebundle_Bundle* spiffebundle_FromX509Bundle(x509bundle_Bundle *bundle);
spiffebundle_Bundle* spiffebundle_FromJWTBundle(jwtbundle_Bundle *bundle);
spiffebundle_Bundle* spiffebundle_FromX509Authorities(const spiffeid_TrustDomain td,
                                                        const X509 **auths);
spiffebundle_Bundle* spiffebundle_FromJWTAuthorities(const spiffeid_TrustDomain td,
                                                const map_string_EVP_PKEY *auths);
spiffeid_TrustDomain spiffebundle_Bundle_TrustDomain(const spiffebundle_Bundle *b);
X509** spiffebundle_Bundle_X509Authorities(spiffebundle_Bundle *b);
void spiffebundle_Bundle_AddX509Authority(spiffebundle_Bundle *b, X509 *auth);
void spiffebundle_Bundle_RemoveX509Authority(spiffebundle_Bundle *b, const X509 *auth);
bool spiffebundle_Bundle_HasX509Authority(spiffebundle_Bundle *b, const X509 *auth);
void spiffebundle_Bundle_SetX509Authorities(spiffebundle_Bundle *b, const X509 **auths);
map_string_EVP_PKEY* spiffebundle_Bundle_JWTAuthorities(spiffebundle_Bundle *b);
EVP_PKEY* spiffebundle_Bundle_FindJWTAuthority(spiffebundle_Bundle *b, 
                                                const string_t keyID, 
                                                bool *suc);
bool spiffebundle_Bundle_HasJWTAuthority(spiffebundle_Bundle *b, 
                                            const string_t keyID);
err_t spiffebundle_Bundle_AddJWTAuthority(spiffebundle_Bundle *b, 
                                            const string_t keyID,
                                            EVP_PKEY *auth);
void spiffebundle_Bundle_RemoveJWTAuthority(spiffebundle_Bundle *b, 
                                            const string_t keyID);
void spiffebundle_Bundle_SetJWTAuthorities(spiffebundle_Bundle *b,
                                            map_string_EVP_PKEY *auths);
bool spiffebundle_Bundle_Empty(spiffebundle_Bundle *b);
struct timespec spiffebundle_Bundle_RefreshHint(spiffebundle_Bundle *b, bool *suc);
void spiffebundle_Bundle_SetRefreshHint(spiffebundle_Bundle *b,
                                        struct timespec *refHint);
void spiffebundle_Bundle_ClearRefreshHint(spiffebundle_Bundle *b);
uint64_t spiffebundle_Bundle_SequenceNumber(spiffebundle_Bundle *b, bool *suc);
void spiffebundle_Bundle_SetSequenceNumber(spiffebundle_Bundle *b, uint64_t *seqNumber);
void spiffebundle_Bundle_ClearSequenceNumber(spiffebundle_Bundle *b);
byte* spiffebundle_Bundle_Marshal(spiffebundle_Bundle *b, err_t *err);
spiffebundle_Bundle* spiffebundle_Bundle_Clone(spiffebundle_Bundle *b);
x509bundle_Bundle* spiffebundle_Bundle_X509Bundle(spiffebundle_Bundle *b);
jwtbundle_Bundle* spiffebundle_Bundle_JWTBundle(spiffebundle_Bundle *b);
spiffebundle_Bundle* spiffebundle_Bundle_GetBundleForTrustDomain(
                                                spiffebundle_Bundle *b,
                                                const spiffeid_TrustDomain td,
                                                err_t *err);
x509bundle_Bundle* spiffebundle_Bundle_GetX509BundleForTrustDomain(
                                                spiffebundle_Bundle *b,
                                                const spiffeid_TrustDomain td,
                                                err_t *err);
jwtbundle_Bundle* spiffebundle_Bundle_GetJWTBundleForTrustDomain(
                                                spiffebundle_Bundle *b,
                                                const spiffeid_TrustDomain td,
                                                err_t *err);
bool spiffebundle_Bundle_Equal(const spiffebundle_Bundle *b1, 
                                const spiffebundle_Bundle *b2);
bool spiffebundle_refreshHintEqual(const struct timespec *t1,
                                    const struct timespec *t2);
bool spiffebundle_sequenceNumberEqual(const uint64_t *a,
                                        const uint64_t *b);
struct timespec* spiffebundle_copyRefreshHint(const struct timespec *ts);
uint64_t* spiffebundle_copySequenceNumber(const uint64_t *seqNum);

#endif