#include "c-spiffe/internal/pemutil/pem.h"

static const char *types_str[] = { "CERTIFICATE", "PRIVATE KEY" };
enum TYPE_IDX { CERT_TYPE, KEY_TYPE };

static void *parseBlock(BIO *bio_mem, const char *type, err_t *err)
{
    /*
    returns the pointer to parsed PEM as a
    X509 certificate or PKCS8 private key info.
    Takes a pointer to BIO, data string for
    the type ("CERTIFICATE" or "PRIVATE KEY"),
    an out pointer to return the raw data and
    an error variable.
    */

    // generic pointer to be returned
    void *parsed_pem = NULL;
    // return variables for the pem name and header
    char *pem_name = NULL, *pem_header = NULL;
    // length of the data read from bio_mem
    long int len_data = 0;
    // pointer to data
    byte *data = NULL;
    int suc = PEM_read_bio(bio_mem, &pem_name, &pem_header, &data, &len_data);

    *err = NO_ERROR;
    // sucessfully read
    if(suc) {
        if(strstr(pem_name, type)) {
            if(strstr(pem_name, types_str[CERT_TYPE])) {
                // read X509 certificate
                // X509 *cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
                X509 *cert = d2i_X509(NULL, (const byte **) &data, len_data);
                parsed_pem = cert;
            } else if(strstr(pem_name, types_str[KEY_TYPE])) {
                // read EVP_PKEY private key
                // EVP_PKEY *pkey =
                //     d2i_PrivateKey(0, NULL, &data, len_data;

                EVP_PKEY *pkey = d2i_AutoPrivateKey(
                    NULL, (const byte **) &data, len_data);
                parsed_pem = pkey;
            } else {
                // PEM type not supported
                *err = ERR_UNSUPPORTED_TYPE;
            }
        } else {
            // diverging type
            *err = ERR_DIVERGING_TYPE;
        }
    } else {
        // no PEM data found or nothing left to read
        *err = ERR_EOF;
    }

    OPENSSL_free(pem_name);
    OPENSSL_free(pem_header);
    // OPENSSL_free(data);
    return parsed_pem;
}

static void **parseBlocks(const byte *pem_byte, const char *type, err_t *err)
{
    // bio_mem MUST be initialized just one time
    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, (const char *) pem_byte);

    // dynamic array of parsed blocks
    void **parsed_blocks_arr = NULL;

    while(true) {
        void *block = parseBlock(bio_mem, type, err);

        if(block && !(*err)) {
            // insert new block
            arrput(parsed_blocks_arr, block);
        } else if(*err == ERR_EOF) {
            // end of blocks, stop the loop
            *err = NO_ERROR;
            break;
        } else {
            // type not supported currently or diverging type
            if(*err) {
                for(size_t i = 0, size = arrlenu(parsed_blocks_arr); i < size;
                    ++i) {
                    void *data = parsed_blocks_arr[i];
                    if(!strcmp(type, "CERTIFICATE")) {
                        X509_free((X509 *) data);
                    } else if(!strcmp(type, "PRIVATE KEY")) {
                        EVP_PKEY_free((EVP_PKEY *) data);
                    }
                }
                arrfree(parsed_blocks_arr);
                parsed_blocks_arr = NULL;
                break;
            }
        }
    }
    BIO_free(bio_mem);

    return parsed_blocks_arr;
}

X509 **pemutil_ParseCertificates(const byte *bytes, err_t *err)
{
    // array of X509 certificates
    X509 **x509_arr = NULL;

    if(bytes) {
        void **objs = parseBlocks(bytes, types_str[CERT_TYPE], err);

        // not NULL and no error
        if(objs && !(*err)) {
            x509_arr = (X509 **) objs;
        }
    } else {
        // null pointer error
        *err = ERR_NULL;
    }

    return x509_arr;
}

EVP_PKEY *pemutil_ParsePrivateKey(const byte *bytes, err_t *err)
{
    EVP_PKEY *pkey = NULL;

    if(bytes) {
        void **objs = parseBlocks(bytes, types_str[KEY_TYPE], err);

        // not NULL and no error
        if(objs && !(*err)) {
            pkey = (EVP_PKEY *) objs[0];

            // free the remaining objects
            for(size_t i = 1, size = arrlenu(objs); i < size; ++i) {
                if(objs[i])
                    EVP_PKEY_free(objs[i]);
            }
        }
        // free array of pointers
        arrfree(objs);
    } else {
        // null pointer error
        *err = ERR_NULL;
    }
    
    return pkey;
}

byte *pemutil_EncodePrivateKey(EVP_PKEY *pkey, err_t *err)
{
    // stb array of raw bytes
    byte *pem_bytes = NULL;
    const int len = i2d_PrivateKey(pkey, NULL);

    *err = NO_ERROR;

    if(len >= 0) {
        arrsetlen(pem_bytes, len);
        byte *tmp = pem_bytes;

        i2d_PrivateKey(pkey, &tmp);
    } else {
        // error while reading
        *err = ERR_READING;
    }

    return pem_bytes;
}

byte **pemutil_EncodeCertificates(X509 **certs, err_t *err)
{
    byte **pem_bytes_arr = NULL;
    *err = NO_ERROR;

    for(size_t i = 0, size = arrlenu(certs); i < size; ++i) {
        const int len = i2d_X509(certs[i], NULL);

        if(len >= 0) {
            byte *pem_bytes = NULL;
            arrsetlen(pem_bytes, len);
            byte *tmp = pem_bytes;

            i2d_X509(certs[i], &tmp);
            arrput(pem_bytes_arr, pem_bytes);
        } else {
            // could not encode one certificate
            *err = ERR_CERTIFICATE_NOT_ENCODED;
            // freeing all stb array alocated so far
            for(size_t i = 0, size = arrlenu(pem_bytes_arr); i < size; ++i) {
                arrfree(pem_bytes_arr[i]);
            }
            arrfree(pem_bytes_arr);
            break;
        }
    }

    return pem_bytes_arr;
}
