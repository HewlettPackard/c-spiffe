#include "bundle/jwtbundle/source.h"
#include "spiffeid/id.h"
#include "spiffetls/listen.h"
#include "spiffetls/mode.h"
#include "spiffetls/option.h"
#include "workload/x509source.h"
#include "workload/jwtsource.h"
#include <unistd.h>

void init_openssl()
{
    SSL_load_error_strings();
    SSL_library_init();
}

void handleConnection(SSL *conn, jwtbundle_Source *source,
                      string_arr_t audience)
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
        // printf("Client says: %s\n", buff);
    }

    char token[1034 * 16];
    sscanf(buff, "%*sAuthorization: Bearer %s", token);

    err_t err;
    jwtsvid_SVID *svid
        = jwtsvid_ParseAndValidate(token, source, audience, &err);
    if(err != NO_ERROR) {
        printf("Invalid token\n");
        /// TODO: send HTTP unauthorized message
    }

    const char message[] = "HTTP/1.1 200 OK\r\n"
                           "Content-Type: text/html\r\n"
                           "Content-Length: 14\r\n\r\n"
                           "Hello, client!";
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

    workloadapi_JWTSource *jwtsource = workloadapi_NewJWTSource(NULL, &err);
    if(err != NO_ERROR) {
        printf("workloadapi_NewJWTSource() failed: error %u\n", err);
        exit(-1);
    }
    err = workloadapi_JWTSource_Start(jwtsource);
    if(err != NO_ERROR) {
        printf("workloadapi_JWTSource_Start() failed: error %u\n", err);
        exit(-1);
    }
    jwtbundle_Bundle *source = jwtbundle_SourceFromSource(jwtsource);

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
        string_t audience = NULL;
        arrput(audience, string_new("spiffe://example.org/server"));
        /// TODO: create jwtbundle_SourceFromSource
        handleConnection(conn, source, audience);
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
