#ifndef INCLUDE_SVID_X509SVID_SVID_H
#define INCLUDE_SVID_X509SVID_SVID_H

#include "c-spiffe/spiffeid/id.h"
#include <openssl/evp.h>
#include <openssl/x509.h>

#ifdef __cplusplus
extern "C" {
#endif

/** X509-SVID object */
typedef struct x509svid_SVID {
    /** ID is the SPIFFE ID of the X509-SVID. */
    spiffeid_ID id;
    /** stb array of X509 certificate pointers. They are the X.509
     * certificates of the X509-SVID. The leaf certificate is the X509-SVID
     * certificate. Any remaining certificates (if any) chain the X509-SVID
     * certificate back to a X.509 root for the trust domain. */
    X509 **certs;
    /** the private key for the X509-SVID. */
    EVP_PKEY *private_key;
} x509svid_SVID;

/**
 * Load loads the X509-SVID from PEM encoded files on disk.
 *
 * \param certfile [in] Certificate file path.
 * \param keyfile [in] Key file path.
 * \param err [out] Variable to get information in the event of error.
 * \returns Parsed X509-SVID object pointer. Must be freed using
 * x509svid_SVID_Free function.
 */
x509svid_SVID *x509svid_Load(const char *certfile, const char *keyfile,
                             err_t *err);

/**
 * Parses the X509-SVID from PEM blocks containing certificate and key
 * bytes. The certificate must be one or more PEM blocks with ASN.1 DER.
 * The key must be a PEM block with PKCS#8 ASN.1 DER.
 *
 * \param certbytes [in] stb array with certificate bytes.
 * \param keybytes [in] stb array with private key bytes.
 * \param err [out] Variable to get information in the event of error.
 * \returns Parsed X509-SVID object pointer. Must be freed using
 * x509svid_SVID_Free function.
 */
x509svid_SVID *x509svid_Parse(const byte *certbytes, const byte *keybytes,
                              err_t *err);

/**
 * ParseRaw parses the X509-SVID from certificate and key bytes. The
 * certificate must be ASN.1 DER (concatenated with no intermediate padding
 * if there are more than one certificate). The key must be a PKCS#8 ASN.1
 * DER.
 *
 * \param certbytes [in] array with certificate bytes.
 * \param certlen [in] length of certificate array in bytes.
 * \param keybytes [in] array with private key bytes.
 * \param keylen [in] length of private key array in bytes.
 * \param err [out] Variable to get information in the event of error.
 * \returns Parsed X509-SVID object pointer. Must be freed using
 * x509svid_SVID_Free function.
 */
x509svid_SVID *x509svid_ParseRaw(const byte *certbytes, const size_t certlen,
                                 const byte *keybytes, const size_t keylen,
                                 err_t *err);

/**
 * Marshals the X509-SVID and returns PEM encoded blocks for the SVID and
 * private key.
 *
 * \param certs [in] stb array of X.509 certificate object pointers.
 * \param pkey [in] private key object pointer.
 * \param err [out] Variable to get information in the event of error.
 * \returns Parsed X509-SVID object pointer. Must be freed using
 * x509svid_SVID_Free function.
 */
x509svid_SVID *x509svid_newSVID(X509 **certs, EVP_PKEY *pkey, err_t *err);
/**
 * Validates the slice of certificates constitutes a valid SVID chain
 * according to the spiffe standard and returns the spiffe id of the leaf
 * certificate.
 *
 * \param certs [in] stb array of X.509 certificate object pointers.
 * \param err [out] Variable to get information in the event of error.
 * \returns Leaf SPIFFE ID.
 */
spiffeid_ID x509svid_validateCertificates(X509 **certs, err_t *err);
spiffeid_ID x509svid_validateLeafCertificate(X509 *cert, err_t *err);
void x509svid_validateSigningCertificates(X509 **certs, err_t *err);
void x509svid_validateKeyUsage(X509 *cert, err_t *err);
x509svid_SVID *x509svid_SVID_GetX509SVID(x509svid_SVID *svid, err_t *err);
EVP_PKEY *x509svid_validatePrivateKey(EVP_PKEY *priv_key, X509 *cert,
                                      err_t *err);
bool x509svid_keyMatches(EVP_PKEY *priv_key, EVP_PKEY *pub_key, err_t *err);

/**
 * Frees a X509-SVID object.
 *
 * \param svid [in] SVID object pointer.
 */
void x509svid_SVID_Free(x509svid_SVID *svid);

/**
 * Returns the default SVID from a list of SVIDS.
 *
 * \param svids [in] SVID object pointer array.
 * \returns First SVID object pointer in array.
 */
x509svid_SVID *x509svid_SVID_GetDefaultX509SVID(x509svid_SVID **svids);

/**
 * Extracts the SPIFFE ID from the URI SAN of the provided certificate. It
 * will return an an error if the certificate does not have exactly one URI
 * SAN with a well-formed SPIFFE ID.
 *
 * \param cert [in] X.509 certificate object pointer.
 * \param err [out] Variable to get information in the event of error.
 * \returns SPIFFE ID of the leaf certificate.
 */
spiffeid_ID x509svid_IDFromCert(X509 *cert, err_t *err);

#ifdef __cplusplus
}
#endif

#endif
