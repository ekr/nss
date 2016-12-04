/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is PRIVATE to SSL.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "pk11func.h"
#include "selfencrypt.h"
#include "ssl.h"
#include "sslt.h"
#include "ssl3encode.h"
#include "sslimpl.h"
#include "tls13con.h"
#include "tls13err.h"
#include "tls13hashstate.h"

/*
 * The cookie is structured as a self-encrypted structure with the
 * inner value being.
 *
 * struct {
 *     uint8 indicator = 0xff;  // To disambiguate from tickets.
 *     uint8 hash;              // The hash function (ssl_auth_type)
 *     opaque state<0..2^16>;   // The hash state.
 * } CookieInner;
 */
SECStatus
tls13_GetHrrCookie(sslSocket *ss,
                   PRUint8 *buf, unsigned int *len, unsigned int maxlen)
{
    unsigned int buflen;
    unsigned char *ret;
    SECStatus rv;
    PK11Context *ctx;
    PRUint8 encodedCookie[1024];  /* Larger than the maximum size. */
    SECItem cookieItem = { siBuffer, encodedCookie, sizeof(encodedCookie) };
#ifdef DEBUG
    unsigned int expectedLen;

    rv = tls13_GetHrrCookieLength(ss, &expectedLen);
    if (rv != SECSuccess) {
        return SECFailure;
    }
#endif

    /* Encode header. */
    rv = ssl3_AppendNumberToItem(&cookieItem, 0xff, 1);
    if (rv != SECSuccess) {
        return SECFailure;
    }
    rv = ssl3_AppendNumberToItem(&cookieItem, tls13_GetHash(ss), 1);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    /* Export the hash. */
    ctx = PK11_CreateDigestContext(
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

    /* Encode the rest of the cookie. */
    rv = ssl3_AppendNumberToItem(&cookieItem, buflen, 2);
    if (rv != SECSuccess) {
        PORT_Free(ret);
        return SECFailure;
    }
    rv = ssl3_AppendToItem(&cookieItem, ret, buflen);
    PORT_Free(ret);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    /* Encrypt right into the buffer. */
    rv = ssl_SelfEncryptProtect(ss,
                                encodedCookie, cookieItem.data - encodedCookie,
                                buf, len, maxlen);
    if (rv != SECSuccess) {
        return SECFailure;
    }

#ifdef DEBUG
    PORT_Assert(expectedLen = *len);

#endif

    return SECSuccess;
}


/* This is unfortunate, but we need the hash size because it's
 * included in the header which is in the prefix. */
SECStatus
tls13_GetHrrCookieLength(sslSocket *ss, unsigned int *length)
{
    unsigned int len;

    switch (tls13_GetHash(ss)) {
        case ssl_hash_sha256:
            len = 308;
            break;
        case ssl_hash_sha384:
            len = 724;
            break;
        default:
            PORT_Assert(0);
            PORT_SetError(SEC_ERROR_INVALID_ARGS);
            return SECFailure;
    }

    len += 1 + 1 + 2;  /* Indicator + hash + length */

    return ssl_SelfEncryptGetProtectedSize(len, length);
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

    PORT_Assert(0); /* Need to rewrite to do decryption. */
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

