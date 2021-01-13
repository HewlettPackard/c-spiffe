#include <openssl/x509.h>
#include "util.h"

X509** x509util_CopyX509Authorities(X509 **certs)
{
    if(certs)
    {
        X509 **new_certs = NULL;
        for(size_t i = 0, size = arrlenu(certs); i < size; ++i)
        {
            X509 *cert = certs[i];
            //ups the ref count, so it is memory safe
            //no need to copy the contents, for now
            if(cert)
                X509_up_ref(cert);
            arrput(new_certs, cert);
        }

        return new_certs;
    }
    return NULL;
}

bool x509util_CertsEqual(X509 **certs1, X509 **certs2)
{
    if(certs1 && certs2)
    {
        if(arrlenu(certs1) == arrlenu(certs2))
        {
            for(size_t i = 0, size = arrlenu(i); i < size; ++i)
            {
                if(X509_cmp(certs1[i], certs2[i]))
                    return false;
            }

            return true;
        }
        else
            return false;
    }
    
    return certs1 == certs2;
}


