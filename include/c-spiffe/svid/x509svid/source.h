#ifndef INCLUDE_SVID_X509SVID_SOURCE_H
#define INCLUDE_SVID_X509SVID_SOURCE_H

#include "c-spiffe/workload/x509source.h"
#include "c-spiffe/svid/x509svid/svid.h"

typedef struct {
    enum { X509SVID_SVID, X509SVID_WORKLOADAPI_X509SOURCE } type;
    union {
        x509svid_SVID *svid;
        workloadapi_X509Source *source;
    } source;
} x509svid_Source;

x509svid_SVID *x509svid_Source_GetX509SVID(x509svid_Source *source,
                                           err_t *err);

x509svid_Source *x509svid_SourceFromSVID(x509svid_SVID *svid);

x509svid_Source *x509svid_SourceFromSource(workloadapi_X509Source *source);

void x509svid_Source_Free(x509svid_Source *source);

#endif // INCLUDE_SVID_X509SVID_SOURCE_H
