#include "spiffetls/tlsconfig/src/config.h"
#include "workload/src/x509source.h"

int main(void)
{
    err_t err;
    workloadapi_X509Source *source = workloadapi_NewX509Source(NULL, &err);
    if(err) {
        printf("workloadapi_NewX509Source() failed: error %u\n", err);
        exit(-1);
    }

    err = workloadapi_X509Source_Start(source);
    if(err) {
        printf("workloadapi_X509Source_Start() failed: error %u\n", err);
        exit(-1);
    }

    spiffeid_ID id = spiffeid_FromString("spiffe://example.com/server", &err);
}