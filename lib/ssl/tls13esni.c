/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 *  struct {
 *      uint8 checksum[4];
 *      KeyShareEntry keys<4..2^16-1>;
 *      CipherSuite cipher_suites<2..2^16-2>;
 *      uint16 padded_length;
 *      uint64 not_before;
 *      uint64 not_after;
 *      Extension extensions<0..2^16-1>;
 *  } ESNIKeys;
 */
#include "nss.h"
#include "nssb64.h"
#include "pk11func.h"
#include "ssl.h"
#include "sslproto.h"
#include "sslimpl.h"
#include "ssl3exthandle.h"
#include "tls13esni.h"
#include "tls13exthandle.h"
#include "tls13hkdf.h"

const char kHkdfPurposeEsniKey[] = "esni key";
const char kHkdfPurposeEsniIv[] = "esni iv";


void
tls13_DestroyESNIKeys(sslESNIKeys *keys) {
    // TODO(ekr@rtfm.com): Implement.
}

SECStatus
tls13_DecodeESNIKeys(const sslSocket *ss, SECItem *data, sslESNIKeys **keysp)
{
    SECStatus rv;
    sslReadBuffer tmp;
    PRUint64 tmpn;
    SECItem shares;
    sslESNIKeys *keys;
    PRUint8 sha256[32];
    sslReader rdr = SSL_READER(data->data, data->len);

    keys = PORT_ZNew(sslESNIKeys);
    PR_INIT_CLIST(&keys->keyShares);

    /* Make a copy. */
    rv = SECITEM_CopyItem(NULL, &keys->data, data);
    if (rv != SECSuccess) {
        goto loser;
    }

    /* Checksum. */
    rv = sslRead_Read(&rdr, 4, &tmp);
    if (rv != SECSuccess) {
        goto loser;
    }

    /* Now check the checksum. */
    rv = PK11_HashBuf(ssl3_HashTypeToOID(ssl_hash_sha256),
                      sha256,
                      SSL_READER_CURRENT(&rdr),
                      SSL_READER_REMAINING(&rdr));
    if (rv != SECSuccess) {
        PORT_Assert(PR_FALSE);
        goto loser;
    }
    if (0 != NSS_SecureMemcmp(tmp.buf, sha256, 4)) {
        goto loser;
    }

    /* Parse the key shares. */
    rv = sslRead_ReadVariable(&rdr, 2, &tmp);
    if (rv != SECSuccess) {
        goto loser;
    }

    shares.data = (unsigned char *)tmp.buf;
    shares.len = tmp.len;
    while (shares.len) {
        /* TODO(ekr@rtfm.com): This generates an alert if it fails. */
        TLS13KeyShareEntry *ks = NULL;

        rv = tls13_DecodeKeyShareEntry(ss, &shares, &ks);
        if (rv != SECSuccess) {
            goto loser;
        }

        PR_APPEND_LINK(&ks->link, &keys->keyShares);
    }

    /* Parse cipher suites. */
    rv = sslRead_ReadVariable(&rdr, 2, &tmp);
    if (rv != SECSuccess) {
        goto loser;
    }
    /* This can't be odd. */
    if (tmp.len & 1) {
        goto loser;
    }
    rv = SECITEM_MakeItem(NULL, &keys->suites, (PRUint8 *)tmp.buf, tmp.len);
    if (rv != SECSuccess) {
        goto loser;
    }

    /* Padded Length */
    rv = sslRead_ReadNumber(&rdr, 2, &tmpn);
    if (rv != SECSuccess) {
        goto loser;
    }
    keys->paddedLength = (PRUint16)tmpn;

    /* Not Before */
    rv = sslRead_ReadNumber(&rdr, 8, &keys->notBefore);
    if (rv != SECSuccess) {
        goto loser;
    }

    /* Not After */
    rv = sslRead_ReadNumber(&rdr, 8, &keys->notAfter);
    if (rv != SECSuccess) {
        goto loser;
    }

    /* Extensions, which we ignore. */
    rv = sslRead_ReadVariable(&rdr, 2, &tmp);
    if (rv != SECSuccess) {
        goto loser;
    }

    /* Check that this is empty. */
    if (SSL_READER_REMAINING(&rdr) > 0) {
        goto loser;
    }

    *keysp = keys;
    return SECSuccess;

loser:
    tls13_DestroyESNIKeys(keys);
    PORT_SetError(SSL_ERROR_RX_MALFORMED_ESNI_KEYS);

    return SECFailure;;
}

/* Encode an ESNI keys structure. We only allow one key
 * share. */
SECStatus
tls13_EncodeESNIKeys(sslSocket *ss, const sslEphemeralKeyPair *keyPair,
                     PRUint16 pad, PRUint64 notBefore, PRUint64 notAfter,
                     sslBuffer *b)
{
    unsigned int savedOffset1, savedOffset2;
    PRUint8 sha256[32];
    SECStatus rv;

    rv = sslBuffer_Skip(b, 4, &savedOffset1);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    /* Length of vector. */
    rv = sslBuffer_AppendNumber(
        b, tls13_SizeOfKeyShareEntry(keyPair->keys->pubKey), 2);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    /* Our one key share. */
    rv = tls13_EncodeKeyShareEntry(b, keyPair);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    /* Cipher suites. */
    (void)ssl3_config_match_init(ss);
    rv = sslBuffer_Skip(b, 2, &savedOffset2);
    if (rv != SECSuccess) {
        return SECFailure;
    }
    for (unsigned int i = 0; i < ssl_V3_SUITES_IMPLEMENTED; i++) {
        SSLVersionRange vrange = {SSL_LIBRARY_VERSION_TLS_1_3,
                                  SSL_LIBRARY_VERSION_TLS_1_3};

        /* Only send cipher suites that are valid in TLS 1.3 */
        ssl3CipherSuiteCfg *suite = &ss->cipherSuites[i];
        if (ssl3_config_match(suite, ss->ssl3.policy, &vrange, ss)) {
            rv = sslBuffer_AppendNumber(b, suite->cipher_suite,
                                        sizeof(ssl3CipherSuite));
            if (rv != SECSuccess) {
                return SECFailure;
            }
        }
    }
    rv = sslBuffer_InsertLength(b, savedOffset2, 2);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    /* Padding Length. Fixed for now. */
    rv = sslBuffer_AppendNumber(b, pad, 2);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    /* Start time. */
    rv = sslBuffer_AppendNumber(b, notBefore, 8);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    /* End time. */
    rv = sslBuffer_AppendNumber(b, notAfter, 8);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    /* No extensions. */
    rv = sslBuffer_AppendNumber(b, 0, 2);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    /* Now compute the checksum. */
    rv = PK11_HashBuf(ssl3_HashTypeToOID(ssl_hash_sha256), sha256,
                      SSL_BUFFER_BASE(b) + 4,
                      SSL_BUFFER_LEN(b) - 4);
    if (rv != SECSuccess) {
        PORT_Assert(PR_FALSE);
        return SECFailure;
    }
    PORT_Memcpy(SSL_BUFFER_BASE(b), sha256, 4);

    return SECSuccess;
}

SECStatus
SSLExp_SetESNIKeyPair(PRFileDesc *fd,
                      SECKEYPrivateKey *privKey,
                      SECKEYPublicKey *pubKey,
                      SSLNamedGroup group)
{
    sslSocket *ss;

    ss = ssl_FindSocket(fd);
    if (!ss) {
        SSL_DBG(("%d: SSL[%d]: bad socket in %s",
                 SSL_GETPID(), fd, __FUNCTION__));
        return SECFailure;
    }

    /* This call checks that the group is non-null. */
    ss->esniPrivateKey = ssl_NewEphemeralKeyPair(
        ssl_LookupNamedGroup(group),
        privKey, pubKey);
    if (!ss->esniPrivateKey) {
        return SECFailure;
    }
    return SECSuccess;
}

SECStatus
SSLExp_GenerateESNIKeyPair(PRFileDesc *fd,
                           SSLNamedGroup group,
                           SECKEYPrivateKey **privKey,
                           SECKEYPublicKey **pubKey,
                           PRUint8 *out,
                           unsigned int *outlen,
                           unsigned int maxlen)
{
    sslSocket *ss;
    SECStatus rv;
    sslEphemeralKeyPair *keyPair = NULL;
    PRUint8 tmp[1024];
    sslBuffer buf = SSL_BUFFER_FIXED(tmp, sizeof(tmp));
    const sslNamedGroupDef *groupDef;

    ss = ssl_FindSocket(fd);
    if (!ss) {
        SSL_DBG(("%d: SSL[%d]: bad socket in %s",
                 SSL_GETPID(), fd, __FUNCTION__));
        return SECFailure;
    };

    groupDef = ssl_LookupNamedGroup(group);
    if (!groupDef || (groupDef->keaType != ssl_kea_ecdh)) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }

    rv = ssl_CreateECDHEphemeralKeyPair(ss, groupDef, &keyPair);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    *pubKey = SECKEY_CopyPublicKey(keyPair->keys->pubKey);
    *privKey = SECKEY_CopyPrivateKey(keyPair->keys->privKey);
    if (!*pubKey || !*privKey) {
        return SECFailure;
    }


    /* Now marshall */
    /* TODO(ekr@rtfm.com): Fill in the values. */
    rv = tls13_EncodeESNIKeys(ss, keyPair, 100, 0, 0, &buf);
    ssl_FreeEphemeralKeyPair(keyPair);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    rv = SECITEM_MakeItem(NULL, &ss->esniKeysRecord, SSL_BUFFER_BASE(&buf),
                          SSL_BUFFER_LEN(&buf));
    if (rv != SECSuccess) {
        return SECFailure;
    }

    if (!NSSBase64_EncodeItem(NULL, (char *)out, maxlen, &ss->esniKeysRecord)) {
        return SECFailure;
    }
    *outlen = strlen((char *)out);

    return SECSuccess;
}

SECStatus
SSLExp_EnableESNI(PRFileDesc *fd,
                  const PRUint8 *esniKeys,
                  unsigned int esniKeysLen,
                  const char *dummySNI)
{
    sslSocket *ss;
    sslESNIKeys *keys = NULL;
    SECItem data = { siBuffer, NULL, 0 };
    SECStatus rv;

    ss = ssl_FindSocket(fd);
    if (!ss) {
        SSL_DBG(("%d: SSL[%d]: bad socket in %s",
                 SSL_GETPID(), fd, __FUNCTION__));
        return SECFailure;
    }

    if (!NSSBase64_DecodeBuffer(NULL, &data, (char *)esniKeys, esniKeysLen)) {
        return SECFailure;
    }
    rv = tls13_DecodeESNIKeys(ss, &data, &keys);
    SECITEM_FreeItem(&data, PR_FALSE);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    keys->dummySni = PORT_Strdup(dummySNI);
    if (!keys->dummySni) {
        tls13_DestroyESNIKeys(keys);
        return SECFailure;
    }

    ss->peerEsniKeys = keys;

    return SECSuccess;
}

SECStatus
tls13_ComputeESNIKeys(sslSocket *ss,
                      TLS13KeyShareEntry *entry,
                      sslKeyPair *keyPair,
                      const ssl3CipherSuiteDef *suite,
                      PRUint8 *clientRandom,
                      ssl3KeyMaterial *keyMat)
{
    PK11SymKey *Z = NULL;
    PK11SymKey *Zx = NULL;
    SECStatus ret = SECFailure;
    PRUint8 hash[64];
    const ssl3BulkCipherDef *cipherDef = ssl_GetBulkCipherDef(suite);
    size_t keySize = cipherDef->key_size;
    size_t ivSize = cipherDef->iv_size +
                    cipherDef->explicit_nonce_size; /* This isn't always going to
                                                     * work, but it does for
                                                     * AES-GCM */
    SECStatus rv;

    rv = tls13_HandleKeyShare(ss, entry, keyPair, suite->prf_hash, &Z);
    if (rv != SECSuccess) {
        goto loser;
    }
    rv = tls13_HkdfExtract(NULL, Z, suite->prf_hash, &Zx);
    if (rv != SECSuccess) {
        goto loser;
    }
    rv = PK11_HashBuf(ssl3_HashTypeToOID(suite->prf_hash),
                      hash, clientRandom, SSL3_RANDOM_LENGTH)   ;
    if (rv != SECSuccess) {
        goto loser;
    }
    rv = tls13_HkdfExpandLabel(Zx, suite->prf_hash,
                               hash,
                               tls13_GetHashSizeForHash(suite->prf_hash),
                               kHkdfPurposeEsniKey, strlen(kHkdfPurposeEsniKey),
                               ssl3_Alg2Mech(cipherDef->calg),
                               keySize,
                               &keyMat->key);
    if (rv != SECSuccess) {
        goto loser;
    }
    rv = tls13_HkdfExpandLabelRaw(Zx, suite->prf_hash,
                                  hash,
                                  tls13_GetHashSizeForHash(suite->prf_hash),
                                  kHkdfPurposeEsniIv, strlen(kHkdfPurposeEsniIv),
                                  keyMat->iv, ivSize);
    if (rv != SECSuccess) {
        goto loser;
    }

    ret = SECSuccess;

loser:
    PK11_FreeSymKey(Z);
    PK11_FreeSymKey(Zx);
    return ret;
}

SECStatus
tls13_ComputeESNIExtension(sslSocket *ss)
{
    ssl3KeyMaterial keyMat;
    ssl3CipherSuite suite;
    const ssl3CipherSuiteDef *suiteDef;
    sslKeyPair *keyPair;
    size_t i;
    PRCList *cur;
    SECStatus rv;
    SECStatus ret = SECFailure;
    TLS13KeyShareEntry *share;
    SSLAEADCipher aead = NULL;
    PRUint8 outBuf[1024];
    int outLen;
    PRUint8 sniBuf[1024];
    PRBool added = PR_FALSE;
    PRUint8 hash[64];
    sslBuffer sni = SSL_BUFFER_FIXED(sniBuf, sizeof(sniBuf));
    PRUint8 zeroes[8] = {0};

    PORT_Memset(&keyMat, 0, sizeof(keyMat));

    if (!ss->peerEsniKeys) {
        return SECSuccess;
    }

    /* TODO(ekr@rtfm.com): Check for expiry. */
    rv = ssl3_ClientFormatServerNameXtn(ss, ss->url, &ss->xtnData,
                                        &sni, &added);
    if (rv != SECSuccess) {
        return SECFailure;
    }
    if (!added) {
        /* No SNI, so no encrypted SNI. */
        return SECSuccess;
    }
    if (ss->peerEsniKeys->paddedLength > SSL_BUFFER_LEN(&sni)) {
        unsigned int paddingRequired = ss->peerEsniKeys->paddedLength - SSL_BUFFER_LEN(&sni);
        while (paddingRequired--) {
            rv = sslBuffer_AppendNumber(&sni, 0, 1);
            if (rv != SECSuccess) {
                return SECFailure;
            }
        }
    }

    /* Pick the group.
     * TODO(ekr@rtfm.com): Don't let this get too far away from our
     * favorite group.
     */
    for (i = 0; i < SSL_NAMED_GROUP_COUNT; ++i) {
        for (cur = PR_NEXT_LINK(&ss->peerEsniKeys->keyShares);
             cur != &ss->peerEsniKeys->keyShares;
             cur = PR_NEXT_LINK(cur)) {
            if (!ss->namedGroupPreferences[i]) {
                continue;
            }
            share = (TLS13KeyShareEntry *)cur;
            if (share->group->name == ss->namedGroupPreferences[i]->name) {
                goto found;
            }
        }
    }
found:
    if (i == SSL_NAMED_GROUP_COUNT) {
        /* No compatible group. */
        return SECSuccess;
    }

    rv = ssl3_NegotiateCipherSuiteInner(ss, &ss->peerEsniKeys->suites,
                                        SSL_LIBRARY_VERSION_TLS_1_3, &suite);
    if (rv != SECSuccess) {
        return SECSuccess;
    }

    rv = tls13_CreateKeyShare(ss, ss->namedGroupPreferences[i]);
    if (rv != SECSuccess) {
        return SECFailure;
    }
    keyPair = ((sslEphemeralKeyPair *)PR_NEXT_LINK(&ss->ephemeralKeyPairs))->keys;

    suiteDef = ssl_LookupCipherSuiteDef(suite);
    PORT_Assert(suiteDef);
    if (!suiteDef) {
        PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
        return SECFailure;
    }
    aead = tls13_GetAead(ssl_GetBulkCipherDef(suiteDef));
    if (!aead) {
        return SECFailure;
    }
    /* Compute the ESNI keys. Anything after here has to jump to
     * loser to clean up |keyMat|. */
    rv = tls13_ComputeESNIKeys(ss, share, keyPair, suiteDef,
                               ss->ssl3.hs.client_random,
                               &keyMat);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    /* Now encrypt. */
    rv = aead(&keyMat, PR_FALSE /* Encrypt */,
              outBuf, &outLen, sizeof(outBuf),
              SSL_BUFFER_BASE(&sni),
              SSL_BUFFER_LEN(&sni),
              zeroes, sizeof(zeroes));
    if (rv != SECSuccess) {
        goto loser;
    }
    sslBuffer_Clear(&sni);

    rv = PK11_HashBuf(ssl3_HashTypeToOID(suiteDef->prf_hash),
                      hash,
                      ss->peerEsniKeys->data.data,
                      ss->peerEsniKeys->data.len);
    if (rv != SECSuccess) {
        PORT_Assert(PR_FALSE);
        goto loser;
    }

    /* OK, we have the encrypted SNI. Now format the extension
     * so we have it for later. */
    rv = sslBuffer_AppendNumber(&sni, suite, 2);
    if (rv != SECSuccess) {
        goto loser;
    }
    rv = sslBuffer_AppendVariable(&sni, hash,
                                  tls13_GetHashSizeForHash(suiteDef->prf_hash), 2);
    if (rv != SECSuccess) {
        goto loser;
    }
    rv = sslBuffer_AppendVariable(&sni, outBuf, outLen, 2);
    if (rv != SECSuccess) {
        goto loser;
    }

    /* Stash this in xtnData for future use. */
    rv = SECITEM_MakeItem(NULL, &ss->xtnData.esniBuf,
                          SSL_BUFFER_BASE(&sni), SSL_BUFFER_LEN(&sni));
    if (rv != SECSuccess) {
        goto loser;
    }

    ret = SECSuccess;
loser:
    ssl_DestroyKeyMaterial(&keyMat);

    return ret;
}

