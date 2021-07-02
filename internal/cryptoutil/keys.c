#include "c-spiffe/internal/cryptoutil/keys.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>

bool cryptoutil_PublicKeyEqual(EVP_PKEY *pkey1, EVP_PKEY *pkey2)
{
    const int type1 = EVP_PKEY_base_id(pkey1);
    const int type2 = EVP_PKEY_base_id(pkey2);
    if(type1 == EVP_PKEY_RSA) {
        if(type2 == EVP_PKEY_RSA) {
            RSA *rsa_pkey1 = EVP_PKEY_get1_RSA(pkey1),
                *rsa_pkey2 = EVP_PKEY_get1_RSA(pkey2);
            return cryptoutil_RSAPublicKeyEqual(rsa_pkey1, rsa_pkey2);
        }
        return false;
    }

    if(type1 == EVP_PKEY_EC) {
        if(type2 == EVP_PKEY_EC) {
            EC_KEY *ec_pkey1 = EVP_PKEY_get1_EC_KEY(pkey1),
                   *ec_pkey2 = EVP_PKEY_get1_EC_KEY(pkey2);
            return cryptoutil_ECDSAPublicKeyEqual(ec_pkey1, ec_pkey2);
        }
        return false;
    }

    return false;
}

bool cryptoutil_RSAPublicKeyEqual(RSA *key1, RSA *key2)
{
    const BIGNUM *N1 = NULL, *E1 = NULL, *N2 = NULL, *E2 = NULL;

    RSA_get0_key(key1, &N1, &E1, NULL);
    RSA_get0_key(key2, &N2, &E2, NULL);

    return !BN_cmp(N1, N2) && !BN_cmp(E1, E2);
}

bool cryptoutil_ECDSAPublicKeyEqual(const EC_KEY *key1, const EC_KEY *key2)
{
    const EC_GROUP *C1 = EC_KEY_get0_group(key1),
                   *C2 = EC_KEY_get0_group(key2);
    const EC_POINT *P1 = EC_KEY_get0_public_key(key1),
                   *P2 = EC_KEY_get0_public_key(key2);

    return !EC_GROUP_cmp(C1, C2, NULL) && !EC_POINT_cmp(C1, P1, P2, NULL);
}
