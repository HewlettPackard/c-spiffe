#ifndef INCLUDE_WORKLOAD_CLIENT_H
#define INCLUDE_WORKLOAD_CLIENT_H

#include "../../bundle/x509bundle/src/set.h"
#include "../../svid/jwtsvid/src/svid.h"
#include "workload.pb.h"
// #include "../../utils/src/util.h"

#ifdef __cplusplus
extern "C"
{
#endif

x509bundle_Set *workloadapi_parseX509Bundles(const X509SVIDResponse *rep,
                                                err_t *err);
x509bundle_Bundle *workloadapi_parseX509Bundle(string_t id,
                                                const byte *bundle_bytes,
                                                const size_t len,
                                                err_t *err);
#ifdef __cplusplus
}
#endif

#endif