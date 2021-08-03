
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

#include "c-spiffe/bundle/jwtbundle/source.h"
#include "c-spiffe/spiffeid/id.h"
#include "c-spiffe/spiffetls/listen.h"
#include "c-spiffe/spiffetls/mode.h"
#include "c-spiffe/spiffetls/option.h"
#include "c-spiffe/svid/jwtsvid/parse.h"
#include "c-spiffe/workload/jwtsource.h"
#include "c-spiffe/workload/x509source.h"
#include <unistd.h>

void init_openssl()
{
    SSL_load_error_strings();
    SSL_library_init();
}

void handleConnection(SSL *conn)
{
    char buff[1024 * 16];
    const int read = SSL_read(conn, buff, sizeof(buff));

    if(read < 0) {
        ERR_load_CRYPTO_strings();
        SSL_load_error_strings();
        printf("SSL_read() failed: error %d\n", SSL_get_error(conn, read));
        return;
    } else {
        buff[read] = 0;
        printf("Request received\n");
    }

    const char *message = "HTTP/1.1 200 OK\r\n"
                          "Content-Type: text/html\r\n"
                          "Content-Length: 8\r\n\r\n"
                          "Success!";
    const int write = SSL_write(conn, message, strlen(message));
    if(write < 0) {
        ERR_load_CRYPTO_strings();
        SSL_load_error_strings();
        printf("SSL_write() failed: error %d\n", SSL_get_error(conn, write));
    }
}

int main(void)
{
    init_openssl();

    err_t err;
    workloadapi_X509Source *x509source = workloadapi_NewX509Source(NULL, &err);
    if(err != NO_ERROR) {
        printf("workloadapi_NewX509Source() failed: error %u\n", err);
        exit(-1);
    }
    err = workloadapi_X509Source_Start(x509source);
    if(err != NO_ERROR) {
        printf("workloadapi_X509Source_Start() failed: error %u\n", err);
        exit(-1);
    }

    // default port
    const in_port_t port = 8443U;
    spiffeid_ID id = spiffeid_FromString("spiffe://example.org/client", &err);
    spiffetls_ListenMode *mode = spiffetls_MTLSServerWithSource(
        tlsconfig_AuthorizeID(id), x509source);
    spiffetls_listenConfig config
        = { .base_TLS_conf = NULL, .listener_fd = -1 };
    int sock_fd;

    SSL *conn = spiffetls_ListenWithMode(port, mode, &config, &sock_fd, &err);

    if(err != NO_ERROR) {
        printf("spiffetls_ListenWithMode() failed: error %u\n", err);
    } else {
        handleConnection(conn);
        const int fd = SSL_get_fd(conn);
        SSL_shutdown(conn);
        SSL_free(conn);
        close(fd);
        close(sock_fd);
    }

    spiffeid_ID_Free(&id);
    spiffetls_ListenMode_Free(mode);

    return 0;
}
