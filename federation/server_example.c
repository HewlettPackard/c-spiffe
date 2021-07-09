#include "c-spiffe/federation/server.h"

int main(void)
{
    err_t error = NO_ERROR;
    /// TODO: get names as argument
    char domain_name[] = "example.org";
    char cert_filename[] = "./tests/resources/example.org.crt";
    char key_filename[] = "./tests/resources/example.org.key";
    char bundle_filename[] = "./tests/resources/example.org.bundle.jwks";
    spiffebundle_EndpointServer *server = spiffebundle_EndpointServer_New();
    spiffeid_TrustDomain trust_domain
        = spiffeid_TrustDomainFromString(domain_name, &error);
    if(error) {
        fprintf(stderr, "error(%d): Couldn't create trust domain !!!!!",
                error);
        exit(error);
    }
    spiffebundle_Bundle *bundle
        = spiffebundle_Load(trust_domain, bundle_filename, &error);
    spiffebundle_Source *bundle_source = spiffebundle_SourceFromBundle(bundle);
    if(error) {
        fprintf(stderr, "error(%d): Couldn't load from file \"%s\" !!!!!",
                error, bundle_filename);
        exit(error);
    }
    error = spiffebundle_EndpointServer_RegisterBundle(
        server, "/", bundle_source, trust_domain);
    if(error) {
        fprintf(stderr, "error(%d): Couldn't register bundle!!!!!", error);
        exit(error);
    }
    FILE *cert_file = fopen(cert_filename, "r");
    X509 **certs = pemutil_ParseCertificates(FILE_to_bytes(cert_file), &error);
    if(error) {
        fprintf(stderr, "error(%d): Couldn't open certs file!!!!!", error);
        exit(error);
    }
    fprintf(stderr, "certs: %p\n", certs);
    BIO* stderr_bio = BIO_new_fp(stdout,BIO_NOCLOSE);
    
    for(size_t i = 1, size = arrlenu(certs); i < size; ++i) {
       fprintf(stderr, "cert %lu: %p\n",i+1,certs[i]);
       X509_print(stderr_bio,certs[i]);
    }
    FILE *key_file = fopen(key_filename, "r");
    EVP_PKEY *priv_key
        = pemutil_ParsePrivateKey(FILE_to_bytes(key_file), &error);
    if(error) {
        fprintf(stderr, "error(%d): Couldn't open private key file!!!!!",
                error);
        exit(error);
    }
    x509svid_SVID* svid = x509svid_newSVID(certs,priv_key,&error);
    x509svid_Source* source = x509svid_SourceFromSVID(svid);
    spiffebundle_EndpointServer_AddHttpsSpiffeEndpoint(server, domain_name,source, &error);
    // spiffebundle_EndpointServer_AddHttpsWebEndpoint(server, domain_name, certs,
    //                                                 priv_key, &error);
    if(error) {
        fprintf(stderr, "error(%d): Couldn't add endpoint!!!!!", error);
        exit(error);
    }

    error
        = spiffebundle_EndpointServer_ServeEndpoint(server, domain_name, 443);
    if(error) {
        fprintf(stderr, "error(%d): Couldn't serve endpoint!!!!!", error);
        exit(error);
    }
    // wait until ENTER is pressed
    printf("Press ENTER to stop.\n");
    char ch;
    scanf("%c", &ch);
    printf("stopping server\n");
    error = spiffebundle_EndpointServer_Stop(server);
    printf("freeing server\n");
    spiffebundle_EndpointServer_Free(server);
    BIO_free(stderr_bio);
    return 0;
}
