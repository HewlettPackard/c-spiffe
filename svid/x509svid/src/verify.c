#include "verify.h"

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
        spiffeid_ID id = x509svid_IDFromCert(leaf, err);

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
                        spiffeid_ID_TrustDomain(id), 
                        err);
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