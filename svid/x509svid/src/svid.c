#include "svid/x509svid/src/svid.h"
#include "svid/x509svid/src/verify.h"
#include <openssl/bn.h>

x509svid_SVID *x509svid_Load(const char *certfile, const char *keyfile,
                             err_t *err)
{
    FILE *fcert = fopen(certfile, "r");
    if(fcert) {
        byte *certbytes = FILE_to_bytes(fcert);
        fclose(fcert);

        FILE *fkey = fopen(keyfile, "r");
        if(fkey) {
            byte *keybytes = FILE_to_bytes(fkey);
            fclose(fkey);

            x509svid_SVID *svid = x509svid_Parse(certbytes, keybytes, err);
            arrfree(certbytes);
            arrfree(keybytes);

            return svid;
        } else {
            arrfree(certbytes);
            *err = ERROR2;
            return NULL;
        }
    } else {
        *err = ERROR1;
        return NULL;
    }
}

x509svid_SVID *x509svid_Parse(const byte *certbytes, const byte *keybytes,
                              err_t *err)
{
    x509svid_SVID *svid = NULL;
    X509 **certs = pemutil_ParseCertificates(certbytes, err);

    // could not parse certificates
    if(*err) {
        return NULL;
    }

    EVP_PKEY *pkey = pemutil_ParsePrivateKey(keybytes, err);

    // could not parse private key info
    if(!(*err)) {
        svid = x509svid_newSVID(certs, pkey, err);
    }

    for(size_t i = 0, size = arrlenu(certs); i < size; ++i) {
        X509_free(certs[i]);
    }
    arrfree(certs);
    EVP_PKEY_free(pkey);

    return svid;
}

x509svid_SVID *x509svid_ParseRaw(const byte *certbytes, const size_t certlen,
                                 const byte *keybytes, const size_t keylen,
                                 err_t *err)
{
    x509svid_SVID *svid = NULL;
    X509 **certs = x509util_ParseCertificates(certbytes, certlen, err);

    if(!(*err)) {
        EVP_PKEY *pkey = x509util_ParsePrivateKey(keybytes, keylen, err);

        if(!(*err)) {
            svid = x509svid_newSVID(certs, pkey, err);
        }

        for(size_t i = 0, size = arrlenu(certs); i < size; ++i) {
            X509_free(certs[i]);
        }
        arrfree(certs);
        EVP_PKEY_free(pkey);
    }

    return svid;
}

x509svid_SVID *x509svid_newSVID(X509 **certs, EVP_PKEY *pkey, err_t *err)
{
    spiffeid_ID id = x509svid_validateCertificates(certs, err);

    if(!(*err)) {
        EVP_PKEY *signer = x509svid_validatePrivateKey(pkey, certs[0], err);
        if(!(*err)) {
            x509svid_SVID *svid = malloc(sizeof *svid);
            svid->certs = NULL;
            // increase ref count
            for(size_t i = 0, size = arrlenu(certs); i < size; ++i) {
                X509_up_ref(certs[i]);
                arrput(svid->certs, certs[i]);
            }

            svid->id = id;
            svid->private_key = signer;

            return svid;
        } else {
            // private key validation failed
            *err = ERROR2;
        }
    } else {
        // certificate validation failed
        *err = ERROR1;
    }

    return NULL;
}

spiffeid_ID x509svid_validateCertificates(X509 **certs, err_t *err)
{
    if(arrlenu(certs) > 0) {
        spiffeid_ID leaf = x509svid_validateLeafCertificate(certs[0], err);
        if(!(*err)) {
            // leaf certified
            X509 *leaf_cert = certs[0];

            arrdel(certs, 0);
            x509svid_validateSigningCertificates(certs, err);
            arrins(certs, 0, leaf_cert);

            if(!(*err)) {
                // signing certificates are valid
                return leaf;
            }
        }
    } else {
        // empty or null array
        *err = ERROR1;
    }
    return (spiffeid_ID){ { NULL }, NULL };
}

spiffeid_ID x509svid_validateLeafCertificate(X509 *cert, err_t *err)
{
    spiffeid_ID id = x509svid_IDFromCert(cert, err);

    if(!(*err)) {
        if(!X509_check_ca(cert)) {
            x509svid_validateKeyUsage(cert, err);
            if(!(*err))
                return id;
        } else {
            // leaf is CA
            *err = ERROR2;
        }

        spiffeid_ID_Free(&id);
    } else {
        // cannot get leaf certificate spiffe ID
        *err = ERROR1;
    }

    return (spiffeid_ID){ { NULL }, NULL };
}

void x509svid_validateSigningCertificates(X509 **certs, err_t *err)
{
    *err = NO_ERROR;
    for(size_t i = 0, size = arrlenu(certs); i < size; ++i) {
        if(!X509_check_ca(certs[i])) {
            // certificate is not CA
            *err = ERROR1;
            return;
        }

        const uint32_t usage = X509_get_key_usage(certs[i]);

        if(!(usage & KU_DIGITAL_SIGNATURE)) {
            // digital signature flag not set
            *err = ERROR2;
            return;
        }
    }
}

void x509svid_validateKeyUsage(X509 *cert, err_t *err)
{
    const uint32_t usage = X509_get_key_usage(cert);
    *err = NO_ERROR;

    if(!(usage & KU_DIGITAL_SIGNATURE)) {
        // digital signature flag not set
        *err = ERROR1;
    } else if(usage & KU_KEY_CERT_SIGN) {
        // key cert sign is set
        *err = ERROR2;
    } else if(usage & KU_CRL_SIGN) {
        // key crl sign is set
        *err = ERROR3;
    }
}

x509svid_SVID *x509svid_SVID_GetX509SVID(x509svid_SVID *svid, err_t *err)
{
    *err = NO_ERROR;
    return svid;
}

EVP_PKEY *x509svid_validatePrivateKey(EVP_PKEY *priv_key, X509 *cert,
                                      err_t *err)
{
    if(priv_key) {
        EVP_PKEY *pub_key = X509_get_pubkey(cert);
        bool matched = x509svid_keyMatches(priv_key, pub_key, err);

        if(!(*err)) {
            if(matched) {
                // signer
                EVP_PKEY_up_ref(priv_key);
                return priv_key;
            }
            // leaf certificate and private key do not match
            *err = ERROR3;
            return NULL;
        }
        // either non supported private key or diverging types
        *err = ERROR2;
        return NULL;
    }

    // null private key
    *err = ERROR1;
    return NULL;
}

bool x509svid_keyMatches(EVP_PKEY *priv_key, EVP_PKEY *pub_key, err_t *err)
{
    const int priv_type = EVP_PKEY_base_id(priv_key);
    const int pub_type = EVP_PKEY_base_id(pub_key);

    *err = NO_ERROR;

    if(priv_type == pub_type) {
        if(priv_type == EVP_PKEY_RSA) {
            bool res = false;
            RSA *rsa_priv_key = EVP_PKEY_get1_RSA(priv_key),
                *rsa_pub_key = EVP_PKEY_get1_RSA(pub_key);

            const BIGNUM *p = NULL, *q = NULL;
            const BIGNUM *d = NULL, *e = NULL;
            const BIGNUM *n = NULL;

            RSA_get0_factors(rsa_priv_key, &p, &q);
            RSA_get0_key(rsa_priv_key, NULL, NULL, &d);

            RSA_get0_key(rsa_pub_key, &n, &e, NULL);

            BN_CTX *ctx = BN_CTX_new();
            BIGNUM *pq = BN_new();
            // pq = p*q
            BN_mul(pq, p, q, ctx);

            // n must be equal to p*q
            if(!BN_cmp(n, pq)) {
                // one = 1
                BIGNUM *one = NULL;
                BN_dec2bn(&one, "1");

                // p_1 = p-1, q_1 = q-1
                BIGNUM *p_1 = BN_dup(p), *q_1 = BN_dup(q);
                BN_sub(p_1, p_1, one);
                BN_sub(q_1, q_1, one);

                // phi_n = (p-1)*(q-1)
                BIGNUM *phi_n = BN_new();
                BN_mul(phi_n, p_1, q_1, ctx);

                // mod = (d*e) % phi_n
                BIGNUM *mod = BN_new();
                BN_mod_mul(mod, d, e, phi_n, ctx);

                //(d*e) % phi_n must be 1
                if(BN_is_one(mod))
                    res = true;

                BN_free(one);
                BN_free(p_1);
                BN_free(q_1);
                BN_free(phi_n);
                BN_free(mod);
            }

            BN_free(pq);
            BN_CTX_free(ctx);
            return res;
        }

        if(priv_type == EVP_PKEY_EC) {
            bool res = false;
            EC_KEY *ec_priv_key = EVP_PKEY_get1_EC_KEY(priv_key),
                   *ec_pub_key = EVP_PKEY_get1_EC_KEY(pub_key);

            const BIGNUM *n = EC_KEY_get0_private_key(ec_priv_key);
            const EC_GROUP *priv_group = EC_KEY_get0_group(ec_priv_key);

            const EC_POINT *ec_pub_point = EC_KEY_get0_public_key(ec_pub_key);
            const EC_GROUP *pub_group = EC_KEY_get0_group(ec_pub_key);

            BN_CTX *ctx = BN_CTX_new();

            // groups must be equal
            if(!EC_GROUP_cmp(priv_group, pub_group, ctx)) {
                // r = G * n, G being the generator point
                EC_POINT *r = EC_POINT_new(priv_group);
                EC_POINT_mul(priv_group, r, n, NULL, NULL, ctx);

                // r must be equal to ec_pub_point
                if(!EC_POINT_cmp(priv_group, ec_pub_point, r, ctx))
                    res = true;

                EC_POINT_free(r);
            }

            BN_CTX_free(ctx);

            return res;
        }

        // type not supported
        *err = ERROR2;
    }

    // diverging types
    *err = ERROR1;
    return false;
}

void x509svid_SVID_Free(x509svid_SVID *svid)
{
    if(svid) {
        spiffeid_ID_Free(&(svid->id));

        for(size_t i = 0, size = arrlenu(svid->certs); i < size; ++i) {
            X509_free(svid->certs[i]);
        }
        arrfree(svid->certs);

        EVP_PKEY_free(svid->private_key);

        free(svid);
    }
}

x509svid_SVID *x509svid_SVID_GetDefaultX509SVID(x509svid_SVID **svids)
{
    if(arrlenu(svids) > 0) {
        return svids[0];
    }
    return NULL;
}

spiffeid_ID x509svid_IDFromCert(X509 *cert, err_t *err)
{
    spiffeid_ID id = { NULL, NULL };
    if(cert) {
        const int nid = NID_subject_alt_name;
        STACK_OF(GENERAL_NAME) *san_names
            = X509_get_ext_d2i(cert, nid, NULL, NULL);
        int san_name_num = sk_GENERAL_NAME_num(san_names);

        if(san_name_num == 1) {
            const GENERAL_NAME *name = sk_GENERAL_NAME_value(san_names, 0);
            string_t uri_name = string_new(
                (const char *) name->d.uniformResourceIdentifier->data);

            id = spiffeid_FromString(uri_name, err);
            arrfree(uri_name);
        } else if(san_name_num == 0) {
            // certificate contains no URI SAN
            *err = ERROR1;
        } else {
            // certificate contains more than one URI SAN
            *err = ERROR2;
        }

        sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
    } else {
        // null certificate
        *err = ERROR3;
    }

    return id;
}
