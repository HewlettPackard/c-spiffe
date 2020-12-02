#include "../include/util.h"

X509** x509util_CopyX509Authorities(const X509 **certs)
{
    //dummy
    return NULL;
}

bool x509util_CertsEqual(const X509 **certs1, const X509 **certs2)
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
    }
    
    return false;
}

/**
 * TODO: how is it different from pemutil_EncodeCertificates?
 * Answer: we have to use DER format, instead of PEM (??)
 */
byte** x509util_RawCertsFromCerts(const X509 **certs)
{
    //dummy
    return NULL;
}

byte* x509util_ConcatRawCertsFromCerts(const X509 **certs)
{
    //dummy
    return NULL;
}
