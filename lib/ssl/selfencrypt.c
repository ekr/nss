/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is PRIVATE to SSL.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "blapit.h"
#include "pk11func.h"
#include "ssl.h"
#include "sslt.h"
#include "ssl3encode.h"
#include "sslimpl.h"
#include "selfencrypt.h"

static SECStatus
ssl_MacBuffer(PK11SymKey *key, CK_MECHANISM_TYPE mech,
              const unsigned char *in, unsigned int len,
              unsigned char *mac, unsigned int macLen)
{
    PK11Context *ctx = NULL;
    SECItem macParam = { 0, NULL, 0 };
    unsigned int computedLen;
    SECStatus rv;

    ctx = PK11_CreateContextBySymKey(mech, CKA_SIGN, key, &macParam);
    if (!ctx) {
        PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
        goto loser;
    }

    rv = PK11_DigestBegin(ctx);
    if (rv != SECSuccess) {
        PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
        goto loser;
    }

    rv = PK11_DigestOp(ctx, in, len);
    if (rv != SECSuccess) {
        PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
        goto loser;
    }

    rv = PK11_DigestFinal(ctx, mac, &computedLen, macLen);
    if (rv != SECSuccess) {
        PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
        goto loser;
    }

    PORT_Assert(macLen == computedLen);
    if (macLen != computedLen) {
        PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
        goto loser;
    }

    PK11_DestroyContext(ctx, PR_TRUE);
    return SECSuccess;

loser:
    if (ctx) {
        PK11_DestroyContext(ctx, PR_TRUE);
    }
    return SECFailure;
}

/*
 * Structure is.
 *
 * struct {
 *   opaque keyName[16];
 *   opaque iv[16];
 *   opaque ciphertext<16..2^16-1>;
 *   opaque mac[32];
 * } SelfEncrypted;
 *
 * We are using AES-CBC + HMAC-SHA256 in Encrypt-then-MAC mode for
 * two reasons:
 *
 * 1. It's what we already used for tickets.
 * 2. We don't have to worry about nonce collisions as much
 *    (the chance is lower because we have a 128-bit nonce
 *    and they are less serious).
 */
SECStatus
ssl_SelfProtect(
    PK11SymKey *encKey, PK11SymKey *macKey,
    const unsigned char *keyName,
    const PRUint8 *in, unsigned int inLen,
    PRUint8 *out, unsigned int *outLen, unsigned int maxOutLen)
{
    unsigned int len;
    unsigned char iv[AES_BLOCK_SIZE];
    SECItem ivItem = { siBuffer, iv, sizeof(iv) };
    unsigned int ciphertextLen =
        (1 + (inLen / AES_BLOCK_SIZE)) * AES_BLOCK_SIZE;
    unsigned char mac[32]; /* SHA-256 */
    SECItem outItem = { siBuffer, out, maxOutLen };
    SECStatus rv;

    /* Generate a random IV */
    rv = PK11_GenerateRandom(iv, sizeof(iv));
    if (rv != SECSuccess) {
        PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
        return SECFailure;
    }

    /* Add header. */
    rv = ssl3_AppendToItem(&outItem, keyName, SELF_ENCRYPTED_KEY_NAME_LEN);
    if (rv != SECSuccess) {
        return SECFailure;
    }
    rv = ssl3_AppendToItem(&outItem, iv, sizeof(iv));
    if (rv != SECSuccess) {
        return SECFailure;
    }
    PORT_Assert(!(ciphertextLen % AES_BLOCK_SIZE));
    rv = ssl3_AppendNumberToItem(&outItem, ciphertextLen, 2);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    rv = PK11_Encrypt(encKey, CKM_AES_CBC_PAD, &ivItem,
                      outItem.data, &len, outItem.len, in, inLen);
    if (rv != SECSuccess) {
        return SECFailure;
    }
    outItem.data += len;
    outItem.len -= len;

    /* MAC the entire output buffer and append the MAC to the end. */
    rv = ssl_MacBuffer(macKey, CKM_SHA256_HMAC,
                       out, outItem.data - out,
                       mac, sizeof(mac));
    if (rv != SECSuccess) {
        return SECFailure;
    }
    rv = ssl3_AppendToItem(&outItem, mac, sizeof(mac));
    if (rv != SECSuccess) {
        return SECFailure;
    }

    *outLen = outItem.data - out;
    return SECSuccess;
}

SECStatus
ssl_SelfUnprotect(
    PK11SymKey *encKey, PK11SymKey *macKey, const unsigned char *keyName,
    const PRUint8 *in, unsigned int inLen,
    PRUint8 *out, unsigned int *outLen, unsigned int maxOutLen)
{
    unsigned char *encodedKeyName;
    unsigned char *iv;
    SECItem ivItem = { siBuffer, NULL, 0 };
    SECItem inItem = { siBuffer, (unsigned char *)in, inLen };
    unsigned char *cipherText;
    PRUint32 cipherTextLen;
    unsigned char *encodedMac;
    unsigned char computedMac[32]; // TODO(ekr@rtfm.com): Hardcoded
    unsigned int bytesToMac;
    SECStatus rv;

    rv = ssl3_ConsumeFromItem(&inItem, &encodedKeyName,
                              SELF_ENCRYPTED_KEY_NAME_LEN);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    rv = ssl3_ConsumeFromItem(&inItem, &iv, AES_BLOCK_SIZE);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    rv = ssl3_ConsumeNumberFromItem(&inItem, &cipherTextLen, 2);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    /* This guarantees we're not over-reading. */
    rv = ssl3_ConsumeFromItem(&inItem, &cipherText, cipherTextLen);
    if (rv != SECSuccess) {
        return SECFailure;
    }
    bytesToMac = inItem.data - in;

    //TODO(ekr@rtfm.com): Constant
    rv = ssl3_ConsumeFromItem(&inItem, &encodedMac, sizeof(computedMac));
    if (rv != SECSuccess) {
        return SECFailure;
    }

    /* Make sure we're at the end of the block. */
    if (inItem.len) {
        PORT_SetError(SEC_ERROR_BAD_DATA);
        return SECFailure;
    }

    /* Now that everything is decoded, we can make progress. */
    /* 1. Check that we have the right key. */
    if (PORT_Memcmp(keyName, encodedKeyName, SELF_ENCRYPTED_KEY_NAME_LEN)) {
        PORT_SetError(SEC_ERROR_NOT_A_RECIPIENT);
        return SECFailure;
    }

    /* 2. Check the MAC */
    rv = ssl_MacBuffer(macKey, CKM_SHA256_HMAC, in, bytesToMac,
                       computedMac, sizeof(computedMac));
    if (rv != SECSuccess) {
        return SECFailure;
    }
    //TODO(ekr@rtfm.com): sizeof -> Constant -
    if (NSS_SecureMemcmp(computedMac, encodedMac, sizeof(computedMac))) {
        PORT_SetError(SEC_ERROR_BAD_DATA); /* TODO(ekr@rtfm.com): new error. */
        return SECFailure;
    }

    /* 3. OK, it verifies, now decrypt. */
    ivItem.data = iv;
    ivItem.len = AES_BLOCK_SIZE;
    rv = PK11_Decrypt(encKey, CKM_AES_CBC_PAD, &ivItem,
                      out, outLen, maxOutLen, cipherText, cipherTextLen);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    return SECSuccess;
}
