#include "c-spiffe/bundle/x509bundle.h"
#include "c-spiffe/workload/x509source.h"
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
    char str[num_bytes + 1] = {};

    BIO_read(bio, str, num_bytes);

    return str;
}

std::string privateKeyToString(EVP_PKEY *pkey)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);

    long num_bytes = BIO_get_mem_data(bio, NULL);
    char str[num_bytes + 1] = {};

    BIO_read(bio, str, num_bytes);

    return str;
}

std::string x509ChainToString(std::vector<X509 *> &cert_chain)
{
    BIO *bio = BIO_new(BIO_s_mem());

    for(auto cert : cert_chain) {
        PEM_write_bio_X509(bio, cert);
    }

    long num_bytes = BIO_get_mem_data(bio, NULL);
    char str[num_bytes + 1] = {};

    BIO_read(bio, str, num_bytes);

    return str;
}

void runServer()
{
    std::string server_address("example.org:50051");

    err_t error = NO_ERROR;
    workloadapi_X509Source *source = workloadapi_NewX509Source(NULL, &error);
    if(error != NO_ERROR) {
        printf("source error! %d\n", (int) error);
    }
    error = workloadapi_X509Source_Start(source);
    if(error != NO_ERROR) {
        printf("source error! %d\n", (int) error);
    }
    x509svid_SVID *svid = workloadapi_X509Source_GetX509SVID(source, &error);
    x509bundle_Bundle *bundle
        = workloadapi_X509Source_GetX509BundleForTrustDomain(
            source, { .name = "example.org" }, &error);
    if(error != NO_ERROR) {
        printf("fetch error! %d\n", (int) error);
    }
    printf("Address: %p\n", svid);

    if(svid) {

        ServerBuilder builder;

        std::vector<X509 *> svid_chain;
        // inserting intermediate certs
        for(size_t i = 0, size = arrlenu(svid->certs); i < size; ++i) {
            svid_chain.push_back(svid->certs[i]);
        }
        // inserting root certs
        std::vector<X509 *> bundle_chain;
        for(size_t i = 0, size = arrlenu(bundle->auths); i < size; ++i) {
            // svid_chain.push_back(bundle->auths[i]);
            bundle_chain.push_back(bundle->auths[i]);
        }

        std::vector<grpc::experimental::IdentityKeyCertPair> kcpairs
            = { { privateKeyToString(svid->private_key),
                  x509ChainToString(svid_chain) } };

        std::shared_ptr<grpc::experimental::StaticDataCertificateProvider>
            cert_prov = std::make_shared<grpc::experimental::StaticDataCertificateProvider>(
                x509ChainToString(bundle_chain), kcpairs);

        auto cred_options
            = grpc::experimental::TlsServerCredentialsOptions(cert_prov);
        
        cred_options.set_root_cert_name("example.org");
        cred_options.set_identity_cert_name("spiffe://example.org/myworkloadA");
        cred_options.watch_root_certs();
        cred_options.watch_identity_key_cert_pairs();

        auto cred = grpc::experimental::TlsServerCredentials(cred_options);

        // grpc::SslServerCredentialsOptions::PemKeyCertPair keycert
        //     = { privateKeyToString(svid->private_key),
        //         x509ChainToString(svid_chain) };

        // grpc::SslServerCredentialsOptions sslOps;
        // sslOps.pem_key_cert_pairs.push_back(keycert);
        // sslOps.pem_root_certs = x509ChainToString(bundle_chain);
        // sslOps.force_client_auth = true;

        builder.AddListeningPort(server_address, cred);

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
