#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct ssl_server_connection {
    int client;
    SSL *ssl;
    void (*service)(SSL *);
} ssl_server_connection;

int create_socket(int port)
{
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if(s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if(bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if(listen(s, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}

void init_openssl()
{
    SSL_load_error_strings();
    ERR_load_crypto_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() { EVP_cleanup(); }

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_method();

    ctx = SSL_CTX_new(method);
    if(!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);

    // Set the key and cert
    if(SSL_CTX_use_certificate_file(ctx, "resources/server.crt",
                                    SSL_FILETYPE_PEM)
       <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if(SSL_CTX_use_PrivateKey_file(ctx, "resources/server.key",
                                   SSL_FILETYPE_PEM)
       <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_load_verify_locations(ctx, "resources/ca.crt", NULL);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
}

int ssl_serve(ssl_server_connection *connection)
{
    int error, ret;

    printf("trying to accept ssl connection\n");
    // Waits for client to initiate TLS handshake

    SSL_set_accept_state(connection->ssl);
    ret = SSL_accept(connection->ssl);

    if(ret < 0) {
        printf("Errno %d\n", errno);
        printf("Connection accept error: %d!\n", ret);
        ERR_print_errors_fp(stderr);
        ERR_print_errors_fp(stdout);
        ret = SSL_get_error(connection->ssl, ret);
        error = ERR_get_error();
        printf("Ret: %d error: %d Errno: %d", ret, error, errno);

    } else {
        printf("Connection accepted!\n");
        connection->service(connection->ssl);
    }

    return 0;
}

void echo_service(SSL *conn)
{
    const int length = 16 * 1024;
    char buffer[length];
    int read = SSL_read(conn, buffer, length);

    // printf("Message from client: %s\n", buffer);

    if(read > 0) {
        SSL_write(conn, buffer, strlen(buffer));
    }
}

void connection_destroy(ssl_server_connection *connection)
{
    SSL_shutdown(connection->ssl);
    SSL_free(connection->ssl);
    close(connection->client);
}

void init_server_connection(ssl_server_connection *connection, SSL_CTX *ctx,
                            int client, void (*service)(SSL *))
{
    printf("Initiating server connection\n");
    connection->client = client;
    connection->ssl = SSL_new(ctx);
    SSL_set_fd(connection->ssl, connection->client);
    connection->service = service;
}

int main(int argc, char *argv[])
{
    int sock;
    SSL_CTX *ctx;
    ssl_server_connection connection;
    init_openssl();
    ctx = create_context();

    configure_context(ctx);

    sock = create_socket(4433);

    /* Handle connections */
    while(1) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);

        printf("Accepting connections\n");

        int client = accept(sock, (struct sockaddr *) &addr, &len);
        if(client < 0) {
            perror("Unable to accept\n");
            exit(EXIT_FAILURE);
        } else {
            // printf("Client %d accepted!\n", client);
        }

        init_server_connection(&connection, ctx, client, echo_service);
        ssl_serve(&connection);
        connection_destroy(&connection);
    }

    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}
