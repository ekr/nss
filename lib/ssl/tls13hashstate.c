/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is PRIVATE to SSL.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "pk11func.h"
#include "ssl.h"
#include "sslt.h"
#include "sslimpl.h"
#include "tls13err.h"
#include "tls13hashstate.h"

SECStatus
tls13_GetHrrCookie(sslSocket *ss,
                   PRUint8 *buf, unsigned int *len, unsigned int maxlen)
{
    unsigned int buflen;
    unsigned char *ret;
    SECStatus rv;

    PK11Context *ctx = PK11_CreateDigestContext(
        ssl3_HashTypeToOID(tls13_GetHash(ss)));
    if (!ctx) {
        FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
        return SECFailure;
    }
    rv = PK11_DigestBegin(ctx);
    if (rv != SECSuccess) {
        FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
        return SECFailure;
    }
    rv = PK11_DigestOp(ctx, ss->ssl3.hs.messages.buf,
                       ss->ssl3.hs.messages.len);
    if (rv != SECSuccess) {
        FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
        return SECFailure;
    }

    ret = PK11_SaveContextAlloc(ctx, NULL, 0, &buflen);
    if (!ret) {
        FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
        return SECFailure;
    }
    PK11_DestroyContext(ctx, PR_TRUE);

    if (buflen > maxlen) {
        FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
        return SECFailure;
    }
    PORT_Memcpy(buf, ret, buflen);
    *len = buflen;
    PORT_Free(ret);

    return SECSuccess;
}


/* Possibly the worst hack ever. */
unsigned int
tls13_GetHrrCookieLength(sslSocket *ss)
{
    unsigned char buf[512];
    unsigned int len;

    SECStatus rv = tls13_GetHrrCookie(ss, buf, &len, sizeof (buf));
    if (rv != SECSuccess) {
        PORT_Assert(0);
        return 0;
    }
    return len;
}

/* Recover the hash state from the cookie.
 *
 * IMPORTANT: In a real implementation we would MAC the state. Right
 * now we just trust it. DO NOT LAND.
 */
SECStatus
tls13_RecoverHashState(sslSocket *ss,
                       unsigned char *cookie,
                       unsigned int cookieLen)
{
    SECStatus rv;
    PK11Context *ctx;
    unsigned char prefix[6];
    unsigned char *ptr = prefix;

    PORT_Assert(!ss->ssl3.hs.recoveredHashState);
    ctx = PK11_CreateDigestContext(
        ssl3_HashTypeToOID(tls13_GetHash(ss)));
    if (!ctx) {
        FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
        return SECFailure;
    }

    rv = PK11_RestoreContext(ctx, cookie, cookieLen);
    if (rv != SECSuccess) {
        FATAL_ERROR(ss, SSL_ERROR_RX_MALFORMED_CLIENT_HELLO, illegal_parameter);
        goto loser;
    }

    ptr = ssl_EncodeUintX(ssl_tls13_cookie_xtn, 2, ptr);
    ptr = ssl_EncodeUintX(2 + cookieLen, 2, ptr);
    ptr = ssl_EncodeUintX(cookieLen, 2, ptr);

    rv = PK11_DigestOp(ctx, prefix, sizeof(prefix));
    if (rv != SECSuccess) {
        FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
        goto loser;
    }
    rv = PK11_DigestOp(ctx, cookie, cookieLen);
    if (rv != SECSuccess) {
        FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
        goto loser;
    }
    ss->ssl3.hs.recoveredHashState = ctx;
    return SECSuccess;

loser:
    PK11_DestroyContext(ctx, PR_TRUE);
    return SECFailure;
}

