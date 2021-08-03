/**

(C) Copyright 2020-2021 Hewlett Packard Enterprise Development LP

 

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

 

    http://www.apache.org/licenses/LICENSE-2.0

 

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.

**/

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
