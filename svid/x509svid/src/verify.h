#ifndef __INCLUDE_SVID_X509SVID_VERIFY_H__
#define __INCLUDE_SVID_X509SVID_VERIFY_H__

#include <openssl/x509.h>
#include "../../../spiffeid/src/id.h"
#include "../../../utils/src/util.h"

spiffeid_ID x509svid_IDFromCert(X509 *cert, err_t *err);

#endif