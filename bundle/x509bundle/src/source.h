#ifndef __INCLUDE_BUNDLE_X509BUNDLE_SOURCE_H__
#define __INCLUDE_BUNDLE_X509BUNDLE_SOURCE_H__

#include "bundle.h"
#include "set.h"

typedef struct x509bundle_Source
{
    enum x509bundle_Source_Cardinality
        {X509BUNDLE_BUNDLE, X509BUNDLE_SET} type;
    union
    {
        x509bundle_Bundle *bundle;
        x509bundle_Set *set;
    } source;
} x509bundle_Source;

x509bundle_Bundle* x509bundle_Source_GetX509BundleForTrustDomain(
                                    x509bundle_Source *s,
                                    const spiffeid_TrustDomain td,
                                    err_t *err);
x509bundle_Source* x509bundle_SourceFromBundle(x509bundle_Bundle *b);
x509bundle_Source* x509bundle_SourceFromSet(x509bundle_Set *s);
void x509bundle_Source_Free(x509bundle_Source *s, bool alloc);

#endif