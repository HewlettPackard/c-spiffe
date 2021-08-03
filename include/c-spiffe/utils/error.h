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

#ifndef INCLUDE_UTILS_ERROR_H
#define INCLUDE_UTILS_ERROR_H

#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Error code enum */
enum enum_err_t {
    NO_ERROR = 0,
    ERR_CANCELLED_STATUS,
    ERR_CLOSING = ERR_CANCELLED_STATUS,
    ERR_OPENING,
    ERR_INVALID_STATUS,
    ERR_CLOSED,
    ERR_BAD_REQUEST,
    ERR_NULL_DATA,
    ERR_TRUSTDOMAIN_NOTAVAILABLE,
    ERR_NULL_BIO,
    ERR_NULL_BUNDLE,
    ERR_INVALID_TRUSTDOMAIN,
    ERR_EMPTY_DATA,
    ERR_NEW_FP,
    ERR_PARSING,
    ERR_NULL,
    ERR_UNKNOWN_TYPE,
    ERR_UNKNOWN_MODE,
    ERR_INVALID_DATA,
    ERR_CERTIFICATE_NOT_ENCODED,
    ERR_UNSUPPORTED_TYPE,
    ERR_DIVERGING_TYPE,
    ERR_EOF,
    ERR_DEFAULT,
    ERR_NULL_ID,
    ERR_CREATE,
    ERR_CONNECT,
    ERR_SET,
    ERR_NOT_ACCEPTED,
    ERR_NO_PEER_CERTIFICATE,
    ERR_GET,
    ERR_NULL_TOKEN,
    ERR_INITIALIZING,
    ERR_UNMATCH,
    ERR_INVALID_ALGORITHM,
    ERR_NULL_JWT,
    ERR_NOT_FOUND,
    ERR_NOAUTHORITY,
    ERR_PAYLOAD,
    ERR_EXPIRED,
    ERR_NULL_CLAIMS,
    ERR_INVALID_CLAIM,
    ERR_INVALID_JWT,
    ERR_INVALID_SVID,
    ERR_NULL_SVID,
    ERR_NULL_STUB,
    ERR_BAD_ARGUMENT,
    ERR_TIMEOUT,
    ERR_NO_MESSAGE,
    ERR_STARTING,
    ERR_STOPPING,
    ERR_CERTIFICATE_VALIDATION,
    ERR_PRIVKEY_VALIDATION,
    ERR_CANNOT_CERTIFICATE,
    ERR_NOT_CA,
    ERR_SIGNATURE_FLAG,
    ERR_CERT_SIGN,
    ERR_CRL_SIGN,
    ERR_NO_URI,
    ERR_MORE_THAN_ONE_URI,
    ERR_READING,
    ERR_LEAF_CA,
    ERR_THREAD,
    ERR_WAITING,
    ERR_EXISTS,
    ERR_TOO_LONG,
    ERR_BAD_PORT
};

typedef enum enum_err_t err_t;

#ifdef __cplusplus
}
#endif

#endif
