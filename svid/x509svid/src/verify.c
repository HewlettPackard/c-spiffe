#include <openssl/pem.h>
#include "../../../internal/x509util/src/util.h"
#include "verify.h"

//maps a certificate on certificate chains
typedef struct map_X509_chains
{
    X509 *key;
    X509 ***value;
} map_X509_chains;

enum {LEAF, INTERMEDIATE, ROOT};

static X509** appendToFreshChain(X509 **chain, X509 *cert)
{
    X509 **newchain = NULL;
    const size_t newsize = arrlenu(chain) + 1;
    arrsetlen(newchain, newsize);
    memcpy(newchain, chain, (newsize - 1) * sizeof *chain);
    newchain[newsize - 1] = cert;

    return newchain;
}

static err_t isValid(X509 *cert, int type, X509 **currchain)
{
    if(arrlenu(currchain) > 0)
    {
        const int last_idx = arrlenu(currchain) - 1;
        X509 *child = currchain[last_idx];

        X509_NAME *subj_name = X509_get_subject_name(cert);
        X509_NAME *auth_name = X509_get_issuer_name(child);

        //child issuer is different from certificate subject
        if(!X509_NAME_cmp(subj_name, auth_name))
            return ERROR1;
    }

    if(type == INTERMEDIATE || type == ROOT)
    {
        //has no child
        if(arrlenu(currchain) == 0)
            return ERROR2;
    }

    return NO_ERROR;
}

static X509*** buildChains(X509*, 
                        map_X509_chains*, 
                        X509**,
                        int*,
                        x509util_CertPool*,
                        x509util_CertPool*,
                        err_t*);

static X509*** considerCandidate(int type,
                X509 *candidate,
                map_X509_chains *cache,
                X509 **currchain,
                int *sigchecks,
                x509util_CertPool *roots,
                x509util_CertPool *inters,
                X509 ***chains,
                err_t *err)
{
    const int MAX_CHAIN_SIG_CHECK = 100;

    for(size_t i = 0, size = arrlenu(currchain); i < size; ++i)
    {
        if(!X509_cmp(candidate, currchain[i]))
            return chains;
    }

    if(!sigchecks)
        sigchecks = malloc(sizeof *sigchecks);

    (*sigchecks)++;
    if(*sigchecks > MAX_CHAIN_SIG_CHECK)
    {
        *err = ERROR1;
        return chains;
    }

    err_t err2 = isValid(candidate, type, currchain);
    if(err2)
        return chains;
        
    if(type == ROOT)
    {
        arrput(chains, appendToFreshChain(currchain, candidate));
    }   
    else if(type == INTERMEDIATE)
    {
        int idx = hmgeti(cache, candidate);
        X509 ***childchains = NULL;
        if(idx >= 0)
        {
            childchains = buildChains(
                candidate, 
                cache, 
                appendToFreshChain(currchain, candidate),
                sigchecks,
                roots,
                inters,
                err);
            hmput(cache, candidate, childchains);
        }

        ///TODO: implement arrpush
        // arrpush(chains, childchains);
    } 
}

static X509*** buildChains(X509 *cert,
                        map_X509_chains *cache,
                        X509 **currchain,
                        int *sigchecks,
                        x509util_CertPool *roots,
                        x509util_CertPool *inters,
                        err_t *err)
{
    int *roots_idcs = x509util_CertPool_findPotentialParents(roots, cert);
    int *inters_idcs = x509util_CertPool_findPotentialParents(inters, cert);
    X509 ***chains = NULL;

    for(size_t i = 0, size = arrlenu(roots_idcs); i < size; ++i)
    {
        const int root_idx = roots_idcs[i];
        chains = considerCandidate(
                    ROOT,
                    roots->certs[root_idx],
                    cache,
                    currchain,
                    sigchecks,
                    roots,
                    inters,
                    chains,
                    err);
    }

    for(size_t i = 0, size = arrlenu(inters_idcs); i < size; ++i)
    {
        const int inter_idx = inters_idcs[i];
        chains = considerCandidate(
                    INTERMEDIATE,
                    inters->certs[inter_idx],
                    cache,
                    currchain,
                    sigchecks,
                    roots,
                    inters,
                    chains,
                    err);
    }

    if(arrlenu(chains) > 0)
    {
        *err = NO_ERROR;
    }
    
    return chains;
}

//verify chain
static X509*** verifyX509(X509 *cert, 
                    x509util_CertPool *roots, 
                    x509util_CertPool *inters, 
                    err_t *err)
{
    *err = NO_ERROR;
    if(cert && roots)
    {
        X509 ***chains = NULL;
        X509 **chain = NULL;
        arrput(chain, cert);

        if(x509util_CertPool_contains(roots, cert))
        {
            //if certificate is root, we already have a chain
            arrput(chains, chain);
        }
        else
        {
            //we have to build the chains
            int sigs;
            chains = buildChains(cert, NULL, chain, &sigs, roots, inters, err);
        }

        return chains;
    }
    else
        //null certificate(s)
        *err = ERROR1;

    return NULL;
}

X509*** x509svid_ParseAndVerify(byte **raw_certs, 
                    x509bundle_Bundle *b, 
                    spiffeid_ID *id, 
                    err_t *err)
{
    X509 **certs = NULL;
    
    for(size_t i = 0, size = arrlenu(raw_certs); i < size; ++i)
    {
        BIO *bio_mem = BIO_new(BIO_s_mem());
        BIO_write(bio_mem, raw_certs[i], arrlen(raw_certs[i]));

        X509 *cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
        if(cert)
        {
            arrput(certs, cert);
        }
        else
        {
            //unable to parse certificate
            *err = ERROR1;
            //free them all
            for(size_t j = 0, size2 = arrlenu(certs); j < size2; ++j)
            {
                X509_free(certs[j]);
            }
            return NULL;
        }
    }

    return x509svid_Verify(certs, b, id, err);
}

X509*** x509svid_Verify(X509 **certs, 
                    x509bundle_Bundle *b, 
                    spiffeid_ID *id, 
                    err_t *err)
{
    //set id to NULL
    memset(id, 0, sizeof *id);
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

                    x509util_CertPool *x509auths = x509util_NewCertPool(
                        x509bundle_Bundle_X509Authorities(bundle));
                    x509util_CertPool *certspool = x509util_NewCertPool(certs);

                    X509 ***chains = verifyX509(leaf, 
                                x509auths,
                                certspool,
                                err);
                    arrins(certs, 0, leaf);

                    x509util_CertPool_Free(x509auths);
                    x509util_CertPool_Free(certspool);

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
    if(cert)
    {
        int nid = NID_subject_alt_name;
        STACK_OF(GENERAL_NAME) *san_names = 
            (STACK_OF(GENERAL_NAME)*) X509_get_ext_d2i(cert, nid, NULL, NULL);
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
    }
    else
        //null certificate
        *err = ERROR3;

    return (spiffeid_ID){{NULL}, NULL};
}