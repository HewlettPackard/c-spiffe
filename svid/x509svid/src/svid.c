#include "../include/svid.h"
#include "../include/verify.h"
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
    
    //could not parse certificates
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

    EVP_PKEY *pkey = pemutil_ParsePrivateKey(keybytes, err);

    //could not parse private key info
    if(*err)
    {
        if(pkey)
            EVP_PKEY_free(pkey);

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

x509svid_SVID* x509svid_newSVID(X509 **certs, 
                                EVP_PKEY *pkey, 
                                err_t *err)
{
    spiffeid_ID id = x509svid_validateCertificates(certs, err);

    if(!(*err))
    {
        EVP_PKEY *signer = x509svid_validatePrivateKey(pkey, certs[0], err);
        if(!(*err))
        {
            x509svid_SVID *svid = malloc(sizeof *svid);
            //increase ref count
            for(size_t i = 0, size = arrlenu(certs); i < size; ++i)
                X509_up_ref(certs[i]);

            svid->certs = certs;
            svid->id = id;
            svid->privateKey = signer;

            return svid;
        }
        else
        {
            //private key validation failed
            *err = ERROR2;
        }
    }
    else
    {
        //certificate validation failed
        *err = ERROR1;
    }

    return NULL;
}

spiffeid_ID x509svid_validateCertificates(X509 **certs, err_t *err)
{
    if(certs)
    {
        if(arrlenu(certs) > 0)
        {
            spiffeid_ID leaf = x509svid_validateLeafCertificate(certs[0], err);
            if(!(*err))
            {
                //leaf certified
                X509 *leaf_cert = certs[0];

                arrdel(certs, 0);
                x509svid_validateSigningCertificates(certs, err);
                arrins(certs, 0, leaf_cert);

                if(!(*err))
                {
                    //signing certificates are valid
                    return leaf;
                }
            }
        }
        else
        {
            //empty array
            *err = ERROR1;
        }
    }
    else
    {
        //null array
        *err = ERROR1;
    }

    return (spiffeid_ID){NULL, NULL};
}

spiffeid_ID x509svid_validateLeafCertificate(X509 *cert, err_t *err)
{
    spiffeid_ID id = x509svid_IDFromCert(cert, err);

    if(!(*err))
    {
        if(!X509_check_ca(cert))
        {
            x509svid_validateKeyUsage(cert, err);
            if(!(*err))
                return id;
        }
        else
        {
            //leaf is CA
            *err = ERROR2;
        }

        spiffeid_ID_Free(&id, false);
    }
    else
    {
        //cannot get leaf certificate spiffe ID
        *err = ERROR1;
    }

    return (spiffeid_ID){NULL, NULL};
}

void x509svid_validateSigningCertificates(X509 **certs, err_t *err)
{
    *err = NO_ERROR;
    for(size_t i = 0, size = arrlenu(certs); i < size; ++i)
    {
        if(!X509_check_ca(certs[i]))
        {
            //certificate is not CA
            *err = ERROR1;
            return;
        }

        const uint32_t usage = X509_get_key_usage(certs[i]);

        if(!(usage & KU_DIGITAL_SIGNATURE))
        {
            //digital signature flag not set
            *err = ERROR2;
            return;
        }
    }
}

void x509svid_validateKeyUsage(X509 *cert, err_t *err)
{
    const uint32_t usage = X509_get_key_usage(cert);
    *err = NO_ERROR;

    if(!(usage & KU_DIGITAL_SIGNATURE))
    {
        //digital signature flag not set
        *err = ERROR1;
    }
    else if(usage & KU_KEY_CERT_SIGN)
    {
        //key cert sign is set
        *err = ERROR2;
    }
    else if(usage & KU_CRL_SIGN)
    {
        //key crl sign is set
        *err = ERROR3;
    }
}

void x509svid_SVID_Marshal(const x509svid_SVID *svid, 
                            byte **rawbytes1, 
                            byte **rawbytes2, 
                            err_t *err)
{
    //dummy
    return;
}

void x509svid_SVID_MarshalRaw(const x509svid_SVID *svid, 
                                byte **rawbytes1, 
                                byte **rawbytes2, 
                                err_t *err)
{
    //dummy
    return;
}

x509svid_SVID* x509svid_SVID_GetX509SVID(x509svid_SVID *svid, 
                                            err_t *err)
{
    *err = NO_ERROR;
    return svid;
}

EVP_PKEY* x509svid_validatePrivateKey(EVP_PKEY *pkey, 
                                                    X509 *cert, 
                                                    err_t *err)
{
    //dummy
    return NULL;
}