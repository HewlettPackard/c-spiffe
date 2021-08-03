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

#ifndef INCLUDE_SPIFFETLS_OPTION_H
#define INCLUDE_SPIFFETLS_OPTION_H

#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    SSL_CTX *base_TLS_conf;
    int dialer_fd;
} spiffetls_dialConfig;

typedef struct {
    SSL_CTX *base_TLS_conf;
    int listener_fd;
} spiffetls_listenConfig;

typedef void (*spiffetls_DialOption)(spiffetls_dialConfig *);

void spiffetls_DialOption_apply(spiffetls_DialOption option,
                                spiffetls_dialConfig *config);

#ifdef __cplusplus
}
#endif

#endif // INCLUDE_SPIFFETLS_MODE_H
