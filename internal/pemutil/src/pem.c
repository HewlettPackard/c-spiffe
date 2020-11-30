#include "../include/pem.h"

#define CERT_TYPE 0
#define KEY_TYPE 1

static const string_t types_str[] = {"CERTIFICATE", "PRIVATE KEY"};

static void* parseBlock(BIO *bio_mem, const string_t type, byte **data, err_t *err)
{
    void *parsed_pem = NULL;
    char *pem_name = NULL;
    int suc = PEM_read_bio(bio_mem, &pem_name, NULL, data, NULL);
    
    *err = NO_ERROR;
    //sucessfully read
    if(suc)
    {
        if(!strcmp(pem_name, type))
        {
            if(!strcmp(pem_name, types_str[CERT_TYPE]))
            {
                //read X509 certificate
                X509 *cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
                parsed_pem = cert;
                
            }
            else if(!strcmp(pem_name, types_str[KEY_TYPE]))
            {
                //read PKCS8 private key
                PKCS8_PRIV_KEY_INFO *pkey_info =
                    PEM_read_bio_PKCS8_PRIV_KEY_INFO(bio_mem, NULL, NULL, NULL);
                parsed_pem = pkey_info;
            }
            //PEM type not supported
            else
                *err = ERROR1;
        }
        //diverging type
        else
            *err = ERROR2;       
    }
    //no PEM data found or nothing left to read
    else
        *err = ERROR3;

    BIO_free(bio_mem);
    return parsed_pem;
}

static void** parseBlocks(const byte *pem_byte)
{
    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, pem_byte);
    
    //dynamic array of parsed blocks
    void **parsed_blocks_arr = NULL;

    
    // dummy
    return NULL;
}

X509** pemutil_ParseCertificate(const byte *bytes, err_t *err)
{
    //array of X509 certificates
    X509 **x509_arr = NULL;
    //dummy
    return NULL;
}

EVP_PKEY* pemutil_ParsePrivateKey(const byte *bytes, err_t *err)
{
    //dummy
    return NULL;
}

byte* pemutil_EncodePKCS8PrivateKey(const EVP_PKEY *pkey, err_t *err)
{
    //dummy
    return NULL;
}

byte* pemutil_EncodeCertificates(const X509 **certs)
{
    //dummy
    return NULL;
}