#include <fstream>
#include <grpcpp/grpcpp.h>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include "c-spiffe/svid/x509svid.h"
#include "c-spiffe/workload/client.h"

#include <openssl/evp.h>
#include <openssl/pem.h>

#include "helloworld.grpc.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

/* using helloworld::HelloRequest;
using helloworld::HelloReply;
using helloworld::Greeter; */

class GreeterClient
{
  public:
    GreeterClient(const std::string &cert, const std::string &key,
                  const std::string &root, const std::string &server)
    {
        grpc::SslCredentialsOptions opts = { root, key, cert };

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

/* void read(const std::string &filename, std::string &data)
{
    std::ifstream file(filename.c_str(), std::ios::in);

    if(file.is_open()) {
        std::stringstream ss;
        ss << file.rdbuf();

        file.close();

        data = ss.str();
    }

    return;
} */

std::string privateKeyToString(EVP_PKEY *pkey)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);

    long num_bytes = BIO_get_mem_data(bio, NULL);
    std::string str(num_bytes, 0);

    BIO_read(bio, str.data(), num_bytes);

    return str;
}

std::string x509ToString(X509 *cert)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, cert);

    long num_bytes = BIO_get_mem_data(bio, NULL);
    std::string str(num_bytes, 0);

    BIO_read(bio, str.data(), num_bytes);

    return str;
}

int main(int argc, char **argv)
{
    /* std::string cert;
    std::string key;
    std::string root; */
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
        printf("SVID Path: %s\n", svid->id.path);
        printf("Trust Domain: %s\n", svid->id.td.name);
        printf("Cert(s) Address: %p\n", svid->certs);
        printf("Key Address: %p\n", svid->private_key);

        x509svid_SVID_Free(svid);
    }

    // read("./resources/client.crt", cert);
    // read("./resources/client.key", key);
    // read("./resources/ca.crt", root);

    //GreeterClient greeter(cert, key, root, server);

    std::string user("world");
    std::string reply = greeter.SayHello(user);

    std::cout << "Greeter received: " << reply << std::endl;

    error = workloadapi_Client_Close(client);
    if(error != NO_ERROR) {
        printf("close error! %d\n", (int) error);
    }
    workloadapi_Client_Free(client);
    if(error != NO_ERROR) {
        printf("client free error! %d\n", (int) error);
    }

    return 0;
}
