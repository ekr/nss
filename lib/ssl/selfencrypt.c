/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is PRIVATE to SSL.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "nss.h"
#include "blapit.h"
#include "pk11func.h"
#include "ssl.h"
#include "sslt.h"
#include "ssl3encode.h"
#include "sslimpl.h"
#include "selfencrypt.h"

#define SELF_ENCRYPT_KEY_NAME_LEN 16
#define SELF_ENCRYPT_KEY_NAME_PREFIX "NSS!"
#define SELF_ENCRYPT_KEY_NAME_PREFIX_LEN 4
#define SELF_ENCRYPT_KEY_VAR_NAME_LEN 12

/* Handle the global self-encryption keys */
static unsigned char self_encrypt_key_name[SELF_ENCRYPT_KEY_NAME_LEN];
static PK11SymKey *self_encrypt_enc_key = NULL;
static PK11SymKey *self_encrypt_mac_key = NULL;

static PRCallOnceType generate_self_encrypt_keys_once;

SECStatus ssl_GetSelfEncryptKeys(sslSocket *ss,
                                  unsigned char **key_name,
                                  PK11SymKey **aes_key, PK11SymKey **mac_key);

SECStatus
ssl_SelfEncryptShutdown(void *appData, void *nssData)
{
    if (self_encrypt_enc_key) {
        PK11_FreeSymKey(self_encrypt_enc_key);
        self_encrypt_enc_key = NULL;
    }
    if (self_encrypt_mac_key) {
        PK11_FreeSymKey(self_encrypt_mac_key);
        self_encrypt_mac_key = NULL;
    }
    PORT_Memset(&generate_self_encrypt_keys_once, 0,
                sizeof(generate_self_encrypt_keys_once));
    return SECSuccess;
}

static PRStatus
ssl_GenerateSelfEncryptKeys(void *data)
{
    SECStatus rv;
    sslSocket *ss = (sslSocket *)data;
    sslServerCertType certType = { ssl_auth_rsa_decrypt, NULL };
    const sslServerCert *sc;
    SECKEYPrivateKey *svrPrivKey;
    SECKEYPublicKey *svrPubKey;

    sc = ssl_FindServerCert(ss, &certType);
    if (!sc || !sc->serverKeyPair) {
        SSL_DBG(("%d: SSL[%d]: No ssl_auth_rsa_decrypt cert and key pair",
                 SSL_GETPID(), ss->fd));
        goto loser;
    }
    svrPrivKey = sc->serverKeyPair->privKey;
    svrPubKey = sc->serverKeyPair->pubKey;
    if (svrPrivKey == NULL || svrPubKey == NULL) {
        SSL_DBG(("%d: SSL[%d]: Pub or priv key(s) is NULL.",
                 SSL_GETPID(), ss->fd));
        goto loser;
    }

    /* Get a copy of the session keys from shared memory. */
    PORT_Memcpy(self_encrypt_key_name, SELF_ENCRYPT_KEY_NAME_PREFIX,
                sizeof(SELF_ENCRYPT_KEY_NAME_PREFIX));
    if (!ssl_GetSessionTicketKeys(svrPrivKey, svrPubKey, ss->pkcs11PinArg,
                                &self_encrypt_key_name[SELF_ENCRYPT_KEY_NAME_PREFIX_LEN],
                                &self_encrypt_enc_key, &self_encrypt_mac_key))
        return PR_FAILURE;

    rv = NSS_RegisterShutdown(ssl_SelfEncryptShutdown, NULL);
    if (rv != SECSuccess)
        goto loser;

    return PR_SUCCESS;

loser:
    ssl_SelfEncryptShutdown(NULL, NULL);
    return PR_FAILURE;
}

SECStatus
ssl_GetSelfEncryptKeys(sslSocket *ss,
                        unsigned char **key_name,
                        PK11SymKey **aes_key,
                        PK11SymKey **mac_key)
{
    if (PR_CallOnceWithArg(&generate_self_encrypt_keys_once,
                           ssl_GenerateSelfEncryptKeys, ss) !=
        PR_SUCCESS)
        return SECFailure;

    if (self_encrypt_enc_key == NULL ||
        self_encrypt_mac_key == NULL)
        return SECFailure;

    *key_name = self_encrypt_key_name;
    *aes_key = self_encrypt_enc_key;
    *mac_key = self_encrypt_mac_key;
    return SECSuccess;
}


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
ssl_SelfEncryptProtectInt(
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
    rv = ssl3_AppendToItem(&outItem, keyName, SELF_ENCRYPT_KEY_NAME_LEN);
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
ssl_SelfEncryptUnprotectInt(
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
                              SELF_ENCRYPT_KEY_NAME_LEN);
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
    if (PORT_Memcmp(keyName, encodedKeyName, SELF_ENCRYPT_KEY_NAME_LEN)) {
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

/* Predict the size of the encrypted data, including padding */
SECStatus
ssl_SelfEncryptGetProtectedSize(unsigned int inLen, unsigned int *outLen)
{
    unsigned int size =
            SELF_ENCRYPT_KEY_NAME_LEN +
            AES_BLOCK_SIZE +
            inLen;
    size = ((size / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE; /* Padded */
    return size + SHA256_LENGTH;
}

SECStatus
ssl_SelfEncryptProtect(
    sslSocket *ss, const PRUint8 *in, unsigned int inLen,
    PRUint8 *out, unsigned int *outLen, unsigned int maxOutLen)
{
    unsigned char *keyName;
    PK11SymKey *encKey;
    PK11SymKey *macKey;
    SECStatus rv;

    /* Get session ticket keys. */
    rv = ssl_GetSelfEncryptKeys(ss, &keyName, &encKey, &macKey);
    if (rv != SECSuccess) {
        SSL_DBG(("%d: SSL[%d]: Unable to get/generate self-encrypt keys.",
                 SSL_GETPID(), ss->fd));
        return SECFailure;
    }

    return ssl_SelfEncryptProtectInt(encKey, macKey, keyName,
                                     in, inLen, out, outLen, maxOutLen);
}

SECStatus
ssl_SelfEncryptUnprotect(
    sslSocket *ss, const PRUint8 *in, unsigned int inLen,
    PRUint8 *out, unsigned int *outLen, unsigned int maxOutLen)
{
    unsigned char *keyName;
    PK11SymKey *encKey;
    PK11SymKey *macKey;
    SECStatus rv;

    /* Get session ticket keys. */
    rv = ssl_GetSelfEncryptKeys(ss, &keyName, &encKey, &macKey);
    if (rv != SECSuccess) {
        SSL_DBG(("%d: SSL[%d]: Unable to get/generate self-encrypt keys.",
                 SSL_GETPID(), ss->fd));
        return SECFailure;
    }

    return ssl_SelfEncryptUnprotectInt(encKey, macKey, keyName,
                                       in, inLen, out, outLen, maxOutLen);
}
