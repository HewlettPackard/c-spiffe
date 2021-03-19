#ifndef INCLUDE_SVID_X509SVID_SOURCE_H
#define INCLUDE_SVID_X509SVID_SOURCE_H

#include "../../../workload/src/x509source.h"
#include "svid.h"

typedef struct {
    enum { X509SVID_SVID, WORKLOADAPI_X509SOURCE } type;
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
