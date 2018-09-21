/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is PRIVATE to SSL.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __tls13esni_h_
#define __tls13esni_h_

struct sslEsniKeysStr {
    SECItem data; /* Stored for later. */
    sslEphemeralKeyPair *privKey;
    const char *dummySni;
    PRCList keyShares; /* List of TLS13KeyShareEntry */
    SECItem suites;
    PRUint16 paddedLength;
    PRUint64 notBefore;
    PRUint64 notAfter;
};

/* Set the ESNI key pair on a socket (server side)
 *
 * fd -- the socket
 * group -- the named group this key corresponds to
 * privKey -- the private key for the key pair
 * pubKey -- the public key for the key pair
 * cipherSuites -- the cipher suites that can be used
 * cipherSuitesCount -- the number of suites in cipherSuites
 * record/recordLen -- the encoded DNS record (not base64)
 */
SECStatus
SSLExp_SetESNIKeyPair(PRFileDesc *fd,
                      SSLNamedGroup group,
                      SECKEYPrivateKey *privKey,
                      SECKEYPublicKey *pubKey,
                      const PRUint16 *cipherSuites,
                      unsigned int cipherSuitesCount,
                      const char *record, unsigned int recordLen);

/* Set the ESNI keys on a client
 *
 * fd -- the socket
 * ensikeys/esniKeysLen -- the ESNI key structure (not base64)
 * dummyESNI -- the dummy ESNI to use (if any)
 */
SECStatus SSLExp_EnableESNI(PRFileDesc *fd, PRUint8 *esniKeys,
                            unsigned int esniKeysLen, const char *dummySNI);
/*
 * Generate an encoded ESNIKeys structure (presumably server side).
 *
 * cipherSuites -- the cipher suites that can be used
 * cipherSuitesCount -- the number of suites in cipherSuites
 * group -- the named group this key corresponds to
 * pubKey -- the public key for the key pair
 * pad -- the length to pad to
 * notBefore/notAfter -- validity range
 * out/outlen/maxlen -- where to output the data
 */
SECStatus SSLExp_EncodeESNIKeys(PRUint16 *cipherSuites, unsigned int cipherSuiteCount,
                                SSLNamedGroup group, SECKEYPublicKey *pubKey,
                                PRUint16 pad, PRUint64 notBefore, PRUint64 notAfter,
                                PRUint8 *out, unsigned int *outlen, unsigned int maxlen);

void tls13_DestroyESNIKeys(sslEsniKeys *keys);
SECStatus tls13_ClientSetupESNI(sslSocket *ss);
SECStatus tls13_ComputeESNIKeys(const sslSocket *ss,
                                TLS13KeyShareEntry *entry,
                                sslKeyPair *keyPair,
                                const ssl3CipherSuiteDef *suite,
                                const PRUint8 *esniKeysHash,
                                const PRUint8 *keyShareBuf,
                                unsigned int keyShareBufLen,
                                const PRUint8 *clientRandom,
                                ssl3KeyMaterial *keyMat);
SECStatus tls13_FormatEsniAADInput(sslBuffer *aadInput,
                                   PRUint8 *keyShare, unsigned int keyShareLen);

SECStatus tls13_ServerDecryptEsniXtn(const sslSocket *ss, PRUint8 *in, unsigned int inLen,
                                     PRUint8 *out, int *outLen, int maxLen);

#endif
