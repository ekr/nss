/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is PRIVATE to SSL.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __selfencrypt_h_
#define __selfencrypt_h_

#include "secmodt.h"

/* Interface for use by the rest of libssl. */
#define SELF_ENCRYPT_KEY_NAME_LEN 16
#define SELF_ENCRYPT_KEY_VAR_NAME_LEN 12

typedef struct sslSocketStr sslSocket;  /* Forward declaration. */

SECStatus ssl_SelfEncryptProtect(
    sslSocket *ss, const PRUint8 *in, unsigned int inLen,
    PRUint8 *out, unsigned int *outLen, unsigned int maxOutLen);
SECStatus ssl_SelfEncryptUnprotect(
    sslSocket *ss, const PRUint8 *in, unsigned int inLen,
    PRUint8 *out, unsigned int *outLen, unsigned int maxOutLen);
SECStatus ssl_SelfEncryptGetProtectedSize(unsigned int inLen,
                                          unsigned int *outLen);

/* Exported for use in unit tests.*/
SECStatus ssl_GetSelfEncryptKeys(sslSocket *ss,
                                  unsigned char **key_name,
                                  PK11SymKey **aes_key, PK11SymKey **mac_key);
SECStatus ssl_SelfEncryptShutdown(void *appData, void *nssData);

SECStatus ssl_SelfEncryptProtectInt(
    PK11SymKey *encKey, PK11SymKey *macKey, const unsigned char *keyName,
    const PRUint8 *in, unsigned int inLen,
    PRUint8 *out, unsigned int *outLen, unsigned int maxOutLen);
SECStatus ssl_SelfEncryptUnprotectInt(
    PK11SymKey *encKey, PK11SymKey *macKey, const unsigned char *keyName,
    const PRUint8 *in, unsigned int inLen,
    PRUint8 *out, unsigned int *outLen, unsigned int maxOutLen);

#endif
