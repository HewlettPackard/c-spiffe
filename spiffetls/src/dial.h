#ifndef INCLUDE_SPIFFETLS_DIAL_H
#define INCLUDE_SPIFFETLS_DIAL_H

#include <openssl/ssl.h>
#include "spiffetls/tlsconfig/src/authorizer.h"

SSL *spiffetls_DialWithMode();

#endif // INCLUDE_SPIFFETLS_DIAL_H
