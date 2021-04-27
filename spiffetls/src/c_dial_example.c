#include "spiffetls/src/dial.h"
#include <unistd.h>

void init_openssl()
{
    SSL_load_error_strings();
    //OpenSSL_add_ssl_algorithms();
    SSL_library_init();
}

int main(void)
{
    init_openssl();
    err_t err;
    printf("info: %s:%d: \n", __FILE__, __LINE__);
    workloadapi_Client *client = workloadapi_NewClient(&err);
    printf("info: %s:%d: \n", __FILE__, __LINE__);
    if(err != NO_ERROR) {
        printf("client error! %d\n", (int) err);
        exit(-1);
    }

    printf("info: %s:%d: \n", __FILE__, __LINE__);
    workloadapi_Client_defaultOptions(client, NULL);

    printf("info: %s:%d: \n", __FILE__, __LINE__);
    err = workloadapi_Client_Connect(client);
    printf("info: %s:%d: \n", __FILE__, __LINE__);
    if(err != NO_ERROR) {
        printf("conn error! %d\n", (int) err);
        exit(-1);
    }

    printf("info: %s:%d: \n", __FILE__, __LINE__);
    x509bundle_Set *set = workloadapi_Client_FetchX509Bundles(client, &err);
    printf("info: %s:%d: \n", __FILE__, __LINE__);

    if(err != NO_ERROR) {
        printf("fetch error! %d\n", (int) err);
        exit(-1);
    }

    printf("info: %s:%d: \n", __FILE__, __LINE__);
    x509bundle_Source *bundle_src = x509bundle_SourceFromSet(set);
    printf("info: %s:%d: \n", __FILE__, __LINE__);

    spiffeid_TrustDomain td = { "example.org" };
    printf("info: %s:%d: \n", __FILE__, __LINE__);
    tlsconfig_Authorizer *authorizer = tlsconfig_AuthorizeMemberOf(td);
    printf("info: %s:%d: \n", __FILE__, __LINE__);

    spiffetls_DialMode *mode
        = spiffetls_TLSClientWithRawConfig(authorizer, bundle_src);

    /* x509svid_SVID *svid
        = x509svid_Load("./resources/good-leaf-and-intermediate.pem",
                        "./resources/key-pkcs8-ecdsa.pem", &err);

    x509svid_Source *svid_src = x509svid_SourceFromSVID(svid);

     spiffetls_DialMode *mode
        = spiffetls_MTLSClientWithRawConfig(authorizer, bundle_src, svid_src); */

    spiffetls_dialConfig config = { .base_TLS_conf = NULL, .dialer_fd = 0 };
    printf("info: %s:%d: \n", __FILE__, __LINE__);

    SSL *conn = spiffetls_DialWithMode((in_port_t) 4433,
                                       /*127.0.0.1*/ (in_addr_t) 0x7F000001,
                                       mode, &config, &err);

    printf("info: %s:%d: - Conn: %p\n", __FILE__, __LINE__, conn);

    if (conn == NULL)
    {
        printf("spiffetls_DialWithMode() failed");
        exit(-1);
    }

    printf("info: %s:%d: \n", __FILE__, __LINE__);
    if(err != NO_ERROR) {
        printf("could not create TLS connection!");
        exit(-1);
    }


    char buff[1024];
    int byytes;
    SSL_write(conn, "will", sizeof("will"));
    byytes = SSL_read(conn, buff, sizeof(buff)); /* get reply & decrypt */
    printf("info: %s:%d: - SSL_read: %p\n", __FILE__, __LINE__, SSL_read);

    buff[byytes] = 0;
    printf("Received: \"%s\"\n", buff);
    printf("info: %s:%d: \n", __FILE__, __LINE__);

    printf("info: %s:%d: \n", __FILE__, __LINE__);
    err = workloadapi_Client_Close(client);
    if(err != NO_ERROR) {
        printf("close error! %d\n", (int) err);
    }
    printf("info: %s:%d: \n", __FILE__, __LINE__);
    workloadapi_Client_Free(client);
    if(err != NO_ERROR) {
        printf("client free error! %d\n", (int) err);
    }

    printf("info: %s:%d: \n", __FILE__, __LINE__);
    spiffetls_DialMode_Free(mode);

    printf("info: %s:%d: \n", __FILE__, __LINE__);

    char buf[1024];
    int bytes;
    printf("info: %s:%d: - SSL_read: %p\n", __FILE__, __LINE__, SSL_read);
    bytes = SSL_read(conn, buf, sizeof(buf)); /* get reply & decrypt */

    const int fd = SSL_get_fd(conn);
    printf("info: %s:%d: \n", __FILE__, __LINE__);
    SSL_shutdown(conn);

    SSL_free(conn);
    printf("info: %s:%d: \n", __FILE__, __LINE__);
    close(fd);
    printf("info: %s:%d: \n", __FILE__, __LINE__);

    return 0;
}