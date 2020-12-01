#include "../include/pem.h"

static const string_t types_str[] = {"CERTIFICATE", "PRIVATE KEY"};
enum TYPE_IDX {CERT_TYPE, KEY_TYPE};

static void* parseBlock(BIO *bio_mem, 
                const string_t type, 
                err_t *err)
{
    /*
    returns the pointer to parsed PEM as a
    X509 certificate or PKCS8 private key info.
    Takes a pointer to BIO, data string for 
    the type ("CERTIFICATE" or "PRIVATE KEY"), 
    an out pointer to return the raw data and 
    an error variable.
    */

    //generic pointer to be returned
    void *parsed_pem = NULL;
    //return variables for the pem name and header
    char *pem_name = NULL, *pem_header = NULL;
    //length of the data read from bio_mem
    long int len_data = 0;
    //pointer to data
    byte **data = NULL;
    int suc = PEM_read_bio(bio_mem, &pem_name, &pem_header, data, &len_data);
    
    *err = NO_ERROR;
    //sucessfully read
    if(suc)
    {
        if(!strcmp(pem_name, type))
        {
            if(!strcmp(pem_name, types_str[CERT_TYPE]))
            {
                //read X509 certificate
                // X509 *cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
                X509 *cert = d2i_X509(NULL, (const byte**) data, len_data);
                parsed_pem = cert;
                
            }
            else if(!strcmp(pem_name, types_str[KEY_TYPE]))
            {
                //read PKCS8 private key
                // PKCS8_PRIV_KEY_INFO *pkey_info =
                //     PEM_read_bio_PKCS8_PRIV_KEY_INFO(bio_mem, NULL, NULL, NULL);
                PKCS8_PRIV_KEY_INFO *pkey_info = 
                    d2i_PKCS8_PRIV_KEY_INFO(NULL, (const byte**) data, len_data);
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
    
    OPENSSL_free(pem_name);
    OPENSSL_free(pem_header);
    // OPENSSL_free(data);
    BIO_free(bio_mem);
    return parsed_pem;
}

static void** parseBlocks(const byte *pem_byte, 
                const string_t type, 
                err_t *err)
{
    //bio_mem MUST be initialized just one time (??)
    /** TODO: check whether BIO keeps track of the
     * already read data.
    */
    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, pem_byte);
    
    //dynamic array of parsed blocks
    void **parsed_blocks_arr = NULL;

    while(true)
    {
        void *block = parseBlock(bio_mem, type, err);
        
        if(block && !(*err))
        {
            arrput(parsed_blocks_arr, block);
        }
        else if(!block)
        {
            break;
        }
        else //non trivial error
        {
            //type not supported currently
            if(*err != ERROR1)
            {
                arrfree(parsed_blocks_arr);
                return NULL;
            }
        }
    }
    *err = NO_ERROR;

    return parsed_blocks_arr;
}

X509** pemutil_ParseCertificates(const byte *bytes, err_t *err)
{
    //array of X509 certificates
    X509 **x509_arr = NULL;

    void **objs = parseBlocks(bytes, types_str[CERT_TYPE], err);
    
    //not NULL and no error
    if(objs && !(*err))
    {
        //maybe check the vality of each object?
        //don't think it is possible, though
        for(size_t i = 0, size = arrlenu(objs); i < size; ++i)
        {
            arrput(x509_arr, (X509*) objs[i]);
        }
    }
    else if(objs)
    {
        //free them all!
        for(size_t i = 0, size = arrlenu(objs); i < size; ++i)
        {
            //free each X509 certificate
            if(objs[i])
                X509_free(objs[i]);
        }
    }
    //free array of pointers
    arrfree(objs);

    return x509_arr;
}

PKCS8_PRIV_KEY_INFO* pemutil_ParsePrivateKey(const byte *bytes, err_t *err)
{
    PKCS8_PRIV_KEY_INFO *pkey = NULL;

    void **objs = parseBlocks(bytes, types_str[CERT_TYPE], err);

    //not NULL and no error
    if(objs && !(*err))
    {
        //maybe check the vality of each object?
        //don't think it is possible, though
        pkey = (PKCS8_PRIV_KEY_INFO*) objs[0];

        //free the remaining objects
        for(size_t i = 1, size = arrlenu(objs); i < size; ++i)
        {
            PKCS8_PRIV_KEY_INFO_free(objs[i]);
        }
    }
    else if(objs)
    {
        //free them all!
        for(size_t i = 0, size = arrlenu(objs); i < size; ++i)
        {
            //free each private key
            if(objs[i])
                PKCS8_PRIV_KEY_INFO_free(objs[i]);
        }
    }
    //free array of pointers
    arrfree(objs);

    return pkey;
}

/**
 * TODO: check if it is better to copy pem_bytes
 * data o a stb array
 */
byte* pemutil_EncodePKCS8PrivateKey(PKCS8_PRIV_KEY_INFO *pkey, int *bytes_len, err_t *err)
{
    //array of raw bytes
    byte *pem_bytes = NULL;
    int len = i2d_PKCS8_PRIV_KEY_INFO(pkey, &pem_bytes);

    if(len >= 0)
        *bytes_len = len;
    //error while reading
    else
        *err = ERROR2;

    return pem_bytes;
}

byte** pemutil_EncodeCertificates(X509 **certs)
{
    byte **pem_bytes_arr = NULL;
    byte *pem_bytes = NULL;

    for(size_t i = 0, size = arrlen(certs); i < size; ++i)
    {
        i2d_X509(certs[i], &pem_bytes);
        
        if(pem_bytes)
            arrput(pem_bytes_arr, pem_bytes);
    }

    return pem_bytes_arr;
}