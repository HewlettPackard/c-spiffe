/*
 * Filename: c-spiffe/requestor/requestor.h
 * Path: c-spiffe/requestor
 * Created Date: Monday, December 21nd 2020, 10:12:28 am
 * Author: Rodrigo Lopes (rlc2@cesar.org.br)
 * 
 * Copyright (c) 2020 CESAR
 */

#ifndef _REQUESTOR_H_
#define _REQUESTOR_H_
#include "../../svid/x509svid/src/svid.h"
  #ifdef __cplusplus
#define EXTERN_C extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C
#define EXTERN_C_END
#endif
EXTERN_C
x509svid_SVID* fetch_SVID();
EXTERN_C_END
#endif /* _REQUESTOR_H_ */
