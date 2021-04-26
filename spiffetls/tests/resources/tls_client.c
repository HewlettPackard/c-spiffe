#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct ssl_client_connection {
    int socket;
    SSL *ssl;
    void (*client)(struct ssl_client_connection *);
} ssl_client_connection;

int create_socket(char *address, int port)
{
    int socket_fd;
    struct sockaddr_in server_address;
    int connect_result;

    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(socket_fd < 0) {
        perror("socket creation failed!");
        exit(EXIT_FAILURE);
    }

    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr(address);
    server_address.sin_port = htons(port);

    connect_result
        = connect(socket_fd, (const struct sockaddr *) &server_address,
                  sizeof(server_address));

    printf("Connect result: %d\n", connect_result);
    return socket_fd;
}

void init_openssl()
{
    SSL_load_error_strings();
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
    if(SSL_CTX_use_certificate_file(ctx, "resources/client.crt",
                                    SSL_FILETYPE_PEM)
       <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if(SSL_CTX_use_PrivateKey_file(ctx, "resources/client.key",
                                   SSL_FILETYPE_PEM)
       <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void init_client_connection(int socket_fd, ssl_client_connection *connection,
                            SSL_CTX *ssl_ctx,
                            void (*client)(ssl_client_connection *))
{
    SSL *ssl = SSL_new(ssl_ctx);
    int ssl_connect_result;
    SSL_set_fd(ssl, socket_fd);
    SSL_set_connect_state(ssl);
    ssl_connect_result = SSL_connect(ssl);
    printf("SSL connect result: %d\n", ssl_connect_result);
    if(ssl_connect_result == -1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    } else {
        connection->client = client;
        connection->ssl = ssl;
        connection->socket = socket_fd;
    }
}

void destroy_client_connection(ssl_client_connection *ssl_client_connection)
{
    SSL_shutdown(ssl_client_connection->ssl);
    SSL_free(ssl_client_connection->ssl);
    close(ssl_client_connection->socket);
}

void say_hello(ssl_client_connection *connection)
{
    char *greet = "hello, from client!\n";
    const int length = 14 * 1024;
    char buffer[length];
    int write;

    write = SSL_write(connection->ssl, greet, strlen(greet));

    printf("Write value: %d\n", write);
    if(write < 0) {
        printf("Error: %d\n", SSL_get_error(connection->ssl, write));
        ERR_load_CRYPTO_strings();
        SSL_load_error_strings();
    }
    SSL_read(connection->ssl, buffer, length);
    printf("reply from server: %s", buffer);
}

int main(int argc, char *argv[])
{
    char *server_address = "127.0.0.1";
    int server_port = 4433;
    int socket;
    SSL_CTX *ssl_ctx;
    ssl_client_connection client_connection;

    init_openssl();

    socket = create_socket(server_address, server_port);

    ssl_ctx = create_context(ssl_ctx);
    configure_context(ssl_ctx);

    init_client_connection(socket, &client_connection, ssl_ctx, say_hello);

    say_hello(&client_connection);
    destroy_client_connection(&client_connection);

    SSL_CTX_free(ssl_ctx);

    return 0;
}
