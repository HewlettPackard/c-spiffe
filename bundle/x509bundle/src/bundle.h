#ifndef __INCLUDE_BUNDLE_X509BUNDLE_BUNDLE_H__
#define __INCLUDE_BUNDLE_X509BUNDLE_BUNDLE_H__

#include <openssl/x509.h>
#include <threads.h>
#include "../../../spiffeid/src/trustdomain.h"
#include "../../../utils/src/util.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef struct x509bundle_Bundle
{
    //bundle trust domain
    spiffeid_TrustDomain td;
    //array of x509 certificate pointers
    X509 **auths;
    //lock
    mtx_t mtx;
} x509bundle_Bundle;

x509bundle_Bundle* x509bundle_New(const spiffeid_TrustDomain td);
x509bundle_Bundle* x509bundle_FromX509Authorities(const spiffeid_TrustDomain td, 
                                                    X509 **auths);
x509bundle_Bundle* x509bundle_Load(const spiffeid_TrustDomain td, 
                                    const string_t path,
                                    err_t *err);
x509bundle_Bundle* x509bundle_Parse(const spiffeid_TrustDomain td, 
                                    const string_t bundle_bytes, 
                                    err_t *err);

spiffeid_TrustDomain x509bundle_Bundle_TrustDomain(const x509bundle_Bundle *b);
X509** x509bundle_Bundle_X509Authorities(x509bundle_Bundle *b);
void x509bundle_Bundle_AddX509Authority(x509bundle_Bundle *b, X509 *auth);
void x509bundle_Bundle_RemoveX509Authority(x509bundle_Bundle *b, X509 *auth);
bool x509bundle_Bundle_HasX509Authority(x509bundle_Bundle *b, X509 *auth);
void x509bundle_Bundle_SetX509Authorities(x509bundle_Bundle *b, X509 **auths);
bool x509bundle_Bundle_Empty(x509bundle_Bundle *b);
bool x509bundle_Bundle_Equal(const x509bundle_Bundle *b1, 
                                const x509bundle_Bundle *b2);
x509bundle_Bundle* x509bundle_Bundle_Clone(x509bundle_Bundle *b);
x509bundle_Bundle* x509bundle_Bundle_GetX509BundleForTrustDomain(
                                            x509bundle_Bundle *b,
                                            const spiffeid_TrustDomain td,
                                            err_t *err);
void x509bundle_Bundle_Free(x509bundle_Bundle *b, bool alloc);

#ifdef __cplusplus
}
#endif

#endif