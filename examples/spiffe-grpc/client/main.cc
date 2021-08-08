#include <fstream>
#include <grpcpp/grpcpp.h>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include "c-spiffe/workload/client.h"
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include "helloworld.grpc.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;


class GreeterClient
{
  public:
    GreeterClient(const std::string &cert, const std::string &key,
                  const std::string &server)
    {
        grpc::SslCredentialsOptions opts = { key, cert };

        stub_ = Greeter::NewStub(
            grpc::CreateChannel(server, grpc::SslCredentials(opts)));
    }

    std::string SayHello(const std::string &user)
    {
        HelloRequest request;
        request.set_name(user);

        HelloReply reply;

        ClientContext context;

        Status status = stub_->SayHello(&context, request, &reply);

        if(status.ok()) {
            return reply.message();
        } else {
            std::cout << status.error_code() << ": " << status.error_message()
                      << std::endl;
            return "RPC failed";
        }
    }

  private:
    std::unique_ptr<Greeter::Stub> stub_;
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

int main(int argc, char **argv)
{
    std::string server{ "localhost:50051" };

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

        GreeterClient greeter(x509ToString(svid->certs[0]),
                              privateKeyToString(svid->private_key), server);

        std::string user("world");
        std::string reply = greeter.SayHello(user);

        std::cout << "Greeter received: " << reply << std::endl;

        x509svid_SVID_Free(svid);
    }

    return 0;
}
