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

#ifndef INCLUDE_SPIFFETLS_LISTEN_H
#define INCLUDE_SPIFFETLS_LISTEN_H

#include "c-spiffe/spiffetls/mode.h"
#include "c-spiffe/spiffetls/option.h"
#include <arpa/inet.h>
#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Establishes a TLS server with given port, address, mode and
 * configuration. If successful, returns a pointer to a established TLS
 * server object.
 *
 * \param port [in] Port number.
 * \param mode [in] Connection mode.
 * \param config [in] Connection configuration.
 * \param sock [out] Server socket fd.
 * \param err [out] Variable to get information in the event of error.
 * \returns Connected server TLS object pointer if successful, NULL otherwise.
 */
SSL *spiffetls_ListenWithMode(in_port_t port, spiffetls_ListenMode *mode,
                              spiffetls_listenConfig *config, int *sock,
                              err_t *err);

/**
 * Establishes a TLS server with given port, address, mode and
 * configuration. If successful, returns a pointer to a established TLS
 * server object.
 *
 * \param port [in] Port number.
 * \param mode [in] Connection mode.
 * \param config [in] Connection configuration.
 * \param sock [out] Server socket fd.
 * \param control_sock [in] socket fd for signaling exit.
 * \param timeout [in] timeout (in milliseconds) used internally with poll().
 * \param err [out] Variable to get information in the event of error.
 * \returns Connected server TLS object pointer if successful, NULL otherwise.
 */                  

SSL *spiffetls_PollWithMode(in_port_t port, spiffetls_ListenMode *mode,
                            spiffetls_listenConfig *config, int *sock,
                            int control_sock, int timeout,
                            err_t *err);
#ifdef __cplusplus
}
#endif

#endif // INCLUDE_SPIFFETLS_DIAL_H
