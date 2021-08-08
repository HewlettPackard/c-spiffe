#include "c-spiffe/workload/client.h"
#include <fstream>
#include <grpcpp/grpcpp.h>
#include <iostream>
#include <memory>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <sstream>
#include <string>

#include "helloworld.grpc.pb.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;


class GreeterServiceImpl final : public Greeter::Service
{
    Status SayHello(ServerContext *context, const HelloRequest *request,
                    HelloReply *reply) override
    {
        std::string prefix("Hello ");

        reply->set_message(prefix + request->name());

        return Status::OK;
    }
};

std::string x509ToString(X509 *cert)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, cert);

    long num_bytes = BIO_get_mem_data(bio, NULL);
    char str[num_bytes];

    BIO_read(bio, str, num_bytes);

    return str;
}

std::string privateKeyToString(EVP_PKEY *pkey)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);

    long num_bytes = BIO_get_mem_data(bio, NULL);
    char str[num_bytes];

    BIO_read(bio, str, num_bytes);

    return str;
}

void runServer()
{
    std::string server_address("localhost:50051");

    err_t error = NO_ERROR;
    workloadapi_Client *client = workloadapi_NewClient(&error);
    if(error != NO_ERROR) {
        printf("client error! %d\n", (int) error);
    }
    workloadapi_Client_defaultOptions(client, NULL);
    error = workloadapi_Client_Connect(client);
    if(error != NO_ERROR) {
        printf("conn error! %d\n", (int) error);
    }

    x509svid_SVID *svid = workloadapi_Client_FetchX509SVID(client, &error);
    if(error != NO_ERROR) {
        printf("fetch error! %d\n", (int) error);
    }
    printf("Address: %p\n", svid);

    if(svid) {

        ServerBuilder builder;

        grpc::SslServerCredentialsOptions::PemKeyCertPair keycert
            = { privateKeyToString(svid->private_key),
                x509ToString(svid->certs[0]) };

        grpc::SslServerCredentialsOptions sslOps;
        sslOps.pem_key_cert_pairs.push_back(keycert);

        builder.AddListeningPort(server_address,
                                 grpc::SslServerCredentials(sslOps));

        GreeterServiceImpl service;
        builder.RegisterService(&service);

        std::unique_ptr<Server> server(builder.BuildAndStart());

        std::cout << "Server listening on " << server_address << std::endl;

        server->Wait();

        x509svid_SVID_Free(svid);
    }
}

int main(int argc, char **argv)
{
    runServer();

    return 0;
}
