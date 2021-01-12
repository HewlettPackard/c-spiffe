#include "verify.h"

//verify chain
static X509*** verifyX509(X509 *cert, X509 **roots, X509 **inters, err_t *err)
{
    X509_STORE *certs_store = X509_STORE_new();
    for(size_t i = 0, size = arrlenu(roots); i < size; ++i)
    {
        X509_STORE_add_cert(certs_store, roots[i]);
    }

    STACK_OF(X509) *certs_stack = sk_X509_new(NULL);
    for(size_t i = 0, size = arrlenu(inters); i < size; ++i)
    {
        sk_X509_push(certs_stack, inters[i]);
    }

    X509_STORE_CTX *certs_ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(certs_ctx, certs_store, cert, certs_stack);

    int ret = X509_verify_cert(certs_ctx);

    if(ret > 0)
    {
        ///TODO: create valid chain
    }
    else
    {
        ///TODO: handle error
    }

    X509_STORE_free(certs_store);
    sk_X509_free(certs_stack);
    X509_STORE_CTX_free(certs_ctx);
}

X509*** x509svid_ParseAndVerify(byte **raw_certs, 
                    x509bundle_Bundle *b, 
                    spiffeid_ID *id, 
                    err_t *err)
{
    //dummy
    return NULL;
}

X509*** x509svid_Verify(X509 **certs, 
                    x509bundle_Bundle *b, 
                    spiffeid_ID *id, 
                    err_t *err)
{
    //set id to NULL
    memset(id, NULL, sizeof *id);
    *err = NO_ERROR;

    if(arrlenu(certs) > 0 && b)
    {
        X509 *leaf = certs[0];
        spiffeid_ID leaf_id = x509svid_IDFromCert(leaf, err);

        if(!(*err))
        {
            const uint32_t usage = X509_get_key_usage(leaf);

            if(!(usage & KU_KEY_CERT_SIGN) && !
                (usage & KU_CRL_SIGN) && 
                !X509_check_ca(leaf))
            {
                x509bundle_Bundle *bundle = 
                    x509bundle_Bundle_GetX509BundleForTrustDomain(
                        b, 
                        spiffeid_ID_TrustDomain(leaf_id), 
                        err);

                if(!(*err))
                {
                    arrdel(certs, 0);
                    X509 ***chains = verifyX509(leaf, 
                                x509bundle_Bundle_X509Authorities(bundle),
                                certs,
                                err);
                    arrins(certs, 0, leaf);

                    if(!(*err))
                    {
                        *id = leaf_id;
                        return chains;
                    }
                    else
                    {
                        //could not verify leaf certificate
                        *err = ERROR6;
                    }
                }
                else
                {
                    //could not get X509 bundle
                    *err = ERROR5;
                }
            }
            else
            {
                //wrong key usage or leaf is CA
                *err = ERROR4;
            }
        }
        else
        {
            //could not get leaf spiffe id
            *err = ERROR3;
        }
    }
    else if(arrlenu(certs) == 0)
    {
        //Empty certificates chain
        *err = ERROR1;
    }
    else
    {
        //bundle is NULL
        *err = ERROR2;
    }

    return NULL;
}

spiffeid_ID x509svid_IDFromCert(X509 *cert, err_t *err)
{
    int nid = NID_subject_alt_name;
    STACK_OF(GENERAL_NAME) *san_names = 
        (GENERAL_NAME*) X509_get_ext_d2i(cert, nid, NULL, NULL);
    int san_name_num = sk_GENERAL_NAME_num(san_names);

    if(san_name_num == 1)
    {
        const GENERAL_NAME *name = sk_GENERAL_NAME_value(san_names, 0);
        string_t uri_name = string_new((char*) name->d.uniformResourceIdentifier->data);

        return spiffeid_FromString(uri_name, err);
    }
    else if(san_name_num == 0)
    {
        //certificate contains no URI SAN
        *err = ERROR1;
    }
    else
    {
        //certificate contains more than one URI SAN
        *err = ERROR2;
    }

    return (spiffeid_ID){{NULL}, NULL};
}