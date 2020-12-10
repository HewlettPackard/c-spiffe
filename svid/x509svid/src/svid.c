#include "../include/svid.h"
#include "../../../internal/pemutil/include/pem.h"

x509svid_SVID* x509svid_Load(const string_t certfile, 
                                const string_t keyfile, 
                                err_t *err)
{
    FILE *fcert = fopen(certfile, "r");
    if(fcert)
    {
        byte *certbytes = FILE_to_bytes(fcert);
        fclose(fcert);

        FILE *fkey = fopen(keyfile, "r");
        if(fkey)
        {
            byte *keybytes = FILE_to_bytes(fkey);
            fclose(fkey);

            return x509svid_Parse(certbytes, keybytes, err);
        }
        else
        {
            *err = ERROR2;
            return NULL;
        }
    }
    else
    {
        *err = ERROR1;
        return NULL;
    }
}

x509svid_SVID* x509svid_Parse(const byte *certbytes, 
                                const byte *keybytes, 
                                err_t *err)
{
    X509 **certs = pemutil_ParseCertificates(certbytes, err);
    
    if(*err)
    {
        ///TODO: check if it is needed to free each X509 obj in certs
        if(certs)
        {
            for(size_t i = 0, size = arrlenu(certs); i < size; ++i)
            {
                X509_free(certs[i]);
            }
            arrfree(certs);
        }
        
        return NULL;
    }

    PKCS8_PRIV_KEY_INFO *pkey = pemutil_ParsePrivateKey(keybytes, err);

    if(*err)
    {
        if(pkey)
            PKCS8_PRIV_KEY_INFO_free(pkey);

        return NULL;
    }

    return x509svid_newSVID(certs, pkey, err);
}

x509svid_SVID* x509svid_ParseRaw(const byte *certbytes, 
                                    const byte *keybytes, 
                                    err_t *err)
{
    //dummy
    return NULL;
}

x509svid_SVID* x509svid_newSVID(const X509 **certs, 
                                const PKCS8_PRIV_KEY_INFO *pkey, 
                                err_t *err)
{
    //dummy
    return NULL;
}