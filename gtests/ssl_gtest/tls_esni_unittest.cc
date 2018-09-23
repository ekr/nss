/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <ctime>

#include "secerr.h"
#include "ssl.h"

#include "gtest_utils.h"
#include "tls_agent.h"
#include "tls_connect.h"

namespace nss_test {

static const char *kDummySni("dummy.invalid");

std::vector<uint16_t> kDefaultSuites = { TLS_AES_128_GCM_SHA256 };
std::vector<uint16_t> kBogusSuites = { 0 };

/* Checksum is a 4-byte array. */
static void UpdateESNIKeysChecksum(DataBuffer* buf) {
    SECStatus rv;
    PRUint8 sha256[32];

    /* Stomp the checksum. */
    PORT_Memset(buf->data() + 2, 0, 4);

    rv = PK11_HashBuf(ssl3_HashTypeToOID(ssl_hash_sha256),
                      sha256,
                      buf->data(), buf->len());
    ASSERT_EQ(SECSuccess, rv);
    buf->Write(2, sha256, 4);
}

static void GenerateESNIKey(time_t windowStart,
                            SSLNamedGroup group,
                            std::vector<uint16_t>& cipherSuites,
                            DataBuffer* record,
                            ScopedSECKEYPublicKey* pubKey = nullptr,
                            ScopedSECKEYPrivateKey* privKey = nullptr) {
  auto groupDef = ssl_LookupNamedGroup(group);
  ASSERT_NE(nullptr, groupDef);

  SECKEYECParams ecParams = { siBuffer, NULL, 0 };
  ASSERT_EQ(SECSuccess, ssl_NamedGroup2ECParams(NULL, groupDef, &ecParams));

  SECKEYPublicKey *pub = nullptr;
  SECKEYPrivateKey *priv = SECKEY_CreateECPrivateKey(&ecParams,
                                                     &pub, nullptr);
  PRUint8 encoded[1024];
  unsigned int encodedLen;

  SECStatus rv = SSL_EncodeESNIKeys(
      &cipherSuites[0], cipherSuites.size(),
      ssl_grp_ec_curve25519,
      pub, 100, windowStart, windowStart + 10,
      encoded, &encodedLen, sizeof(encoded));
  ASSERT_EQ(SECSuccess, rv);
  ASSERT_GT(encodedLen, 0U);

  if (pubKey) {
    pubKey->reset(pub);
  }
  if (privKey) {
    privKey->reset(priv);
  }
  record->Truncate(0);
  record->Write(0, encoded, encodedLen);
}

static void SetupESNI(const std::shared_ptr<TlsAgent>& client,
                      const std::shared_ptr<TlsAgent>& server,
                      SSLNamedGroup group = ssl_grp_ec_curve25519) {
  ScopedSECKEYPublicKey pub;
  ScopedSECKEYPrivateKey priv;
  DataBuffer record;

  GenerateESNIKey(time(nullptr), ssl_grp_ec_curve25519, kDefaultSuites,
                  &record, &pub, &priv);
  SECStatus rv = SSL_SetESNIKeyPair(server->ssl_fd(),
                                    ssl_grp_ec_curve25519,
                                    priv.get(), pub.get(),
                                         &kDefaultSuites[0], kDefaultSuites.size(),
                                    record.data(), record.len());
  ASSERT_EQ(SECSuccess, rv);

  rv = SSL_EnableESNI(client->ssl_fd(),
                      record.data(), record.len(), kDummySni);
  ASSERT_EQ(SECSuccess, rv);
}

static void CheckSNIExtension(const DataBuffer& data) {
  TlsParser parser(data.data(), data.len());
  uint32_t tmp;
  ASSERT_TRUE(parser.Read(&tmp, 2));
  ASSERT_EQ(parser.remaining(), tmp);
  ASSERT_TRUE(parser.Read(&tmp, 1));
  ASSERT_EQ(0U, tmp); /* sni_nametype_hostname */
  DataBuffer name;
  ASSERT_TRUE(parser.ReadVariable(&name, 2));
  ASSERT_EQ(0U, parser.remaining());
  DataBuffer expected(reinterpret_cast<const uint8_t *>(kDummySni), strlen(kDummySni));
  ASSERT_EQ(expected, name);
}

static void ClientInstallESNI(std::shared_ptr<TlsAgent>& agent,
                              const DataBuffer& record, PRErrorCode err = 0 ) {
  SECStatus rv = SSL_EnableESNI(agent->ssl_fd(),
                                record.data(), record.len(), kDummySni);
  if (err == 0) {
    ASSERT_EQ(SECSuccess, rv);
  } else {
    ASSERT_EQ(SECFailure, rv);
    ASSERT_EQ(err, PORT_GetError());
  }
}

TEST_P(TlsAgentTestClient13, ESNIInstall) {
  EnsureInit();
  DataBuffer record;
  GenerateESNIKey(time(0), ssl_grp_ec_curve25519, kDefaultSuites, &record);
  ClientInstallESNI(agent_, record);
}

// The next set of tests fail at setup time.
TEST_P(TlsAgentTestClient13, ESNIInvalidHash) {

  EnsureInit();
  DataBuffer record;
  GenerateESNIKey(time(0), ssl_grp_ec_curve25519, kDefaultSuites, &record);
  record.data()[2]++;
  ClientInstallESNI(agent_, record, SSL_ERROR_RX_MALFORMED_ESNI_KEYS);
}

TEST_P(TlsAgentTestClient13, ESNIInvalidVersion) {

  EnsureInit();
  DataBuffer record;
  GenerateESNIKey(time(0), ssl_grp_ec_curve25519, kDefaultSuites, &record);
  record.Write(0, 0xffff, 2);
  ClientInstallESNI(agent_, record, SSL_ERROR_UNSUPPORTED_VERSION);
}

// The following tests fail by ignoring the ESNI block.
TEST_P(TlsAgentTestClient13, ESNIUnknownGroup) {
  EnsureInit();
  DataBuffer record;
  GenerateESNIKey(time(0), ssl_grp_ec_curve25519, kDefaultSuites, &record);
  record.Write(8, 0xffff, 2); // Fake group
  UpdateESNIKeysChecksum(&record);
  ClientInstallESNI(agent_, record, 0);
  auto filter = MakeTlsFilter<TlsExtensionCapture>(agent_,
                                                   ssl_tls13_encrypted_sni_xtn);
  agent_->Handshake();
  ASSERT_EQ(TlsAgent::STATE_CONNECTING, agent_->state());
  ASSERT_TRUE(!filter->captured());
}

TEST_P(TlsAgentTestClient13, ESNIUnknownCS) {
  EnsureInit();
  DataBuffer record;
  GenerateESNIKey(time(0), ssl_grp_ec_curve25519, kBogusSuites, &record);
  UpdateESNIKeysChecksum(&record);
  ClientInstallESNI(agent_, record, 0);
  auto filter = MakeTlsFilter<TlsExtensionCapture>(agent_,
                                                   ssl_tls13_encrypted_sni_xtn);
  agent_->Handshake();
  ASSERT_EQ(TlsAgent::STATE_CONNECTING, agent_->state());
  ASSERT_TRUE(!filter->captured());
}

TEST_P(TlsAgentTestClient13, ESNINotReady) {
  EnsureInit();
  DataBuffer record;
  GenerateESNIKey(time(0)+1000, ssl_grp_ec_curve25519, kDefaultSuites, &record);
  ClientInstallESNI(agent_, record, 0);
  auto filter = MakeTlsFilter<TlsExtensionCapture>(agent_,
                                                   ssl_tls13_encrypted_sni_xtn);
  agent_->Handshake();
  ASSERT_TRUE(!filter->captured());
}

TEST_P(TlsAgentTestClient13, ESNIExpired) {
  EnsureInit();
  DataBuffer record;
  GenerateESNIKey(time(0)-1000, ssl_grp_ec_curve25519, kDefaultSuites, &record);
  ClientInstallESNI(agent_, record, 0);
  auto filter = MakeTlsFilter<TlsExtensionCapture>(agent_,
                                                   ssl_tls13_encrypted_sni_xtn);
  agent_->Handshake();
  ASSERT_TRUE(!filter->captured());
}

static int32_t SniCallback(TlsAgent *agent, const SECItem* srvNameAddr,
                           PRUint32 srvNameArrSize) {
  EXPECT_EQ(1U, srvNameArrSize);
  SECItem expected = {siBuffer,
                      reinterpret_cast<unsigned char *>(const_cast<char *>("server")), 6 };
  EXPECT_TRUE(
      !SECITEM_CompareItem(&expected,
                           &srvNameAddr[0]));
  return SECSuccess;
}

TEST_P(TlsConnectTls13, ConnectESNI) {
  EnsureTlsSetup();
  SetupESNI(client_, server_);
  auto filter = MakeTlsFilter<TlsExtensionCapture>(client_,
                                                   ssl_server_name_xtn);
  server_->SetSniCallback(SniCallback);
  Connect();
  CheckSNIExtension(filter->extension());
}

TEST_P(TlsConnectTls13, ConnectESNIP256) {
  EnsureTlsSetup();
  SetupESNI(client_, server_, ssl_grp_ec_secp256r1);
  auto filter = MakeTlsFilter<TlsExtensionCapture>(client_,
                                                   ssl_server_name_xtn);
  server_->SetSniCallback(SniCallback);
  Connect();
  CheckSNIExtension(filter->extension());
}

TEST_P(TlsConnectTls13, ConnectMismatchedESNIKeys) {
  EnsureTlsSetup();
  SetupESNI(client_, server_);
  // Now install a new set of keys on the client, so we have a mismatch.
  DataBuffer record;
  GenerateESNIKey(time(0), ssl_grp_ec_curve25519, kDefaultSuites, &record);
  ClientInstallESNI(client_, record, 0);
  auto filter = MakeTlsFilter<TlsExtensionCapture>(client_,
                                                   ssl_server_name_xtn);
  ConnectExpectAlert(server_, illegal_parameter);
  server_->CheckErrorCode(SSL_ERROR_RX_MALFORMED_CLIENT_HELLO);
  CheckSNIExtension(filter->extension());
}

// If we remove the confirmatory ESNI extension, the client will be sad.
TEST_P(TlsConnectTls13, ConnectRemoveESNIExtensionEE) {
  EnsureTlsSetup();
  SetupESNI(client_, server_);
  auto filter = MakeTlsFilter<TlsExtensionDropper>(server_, ssl_tls13_encrypted_sni_xtn);
  filter->EnableDecryption();
  ConnectExpectAlert(client_, missing_extension);
  client_->CheckErrorCode(SSL_ERROR_MISSING_ESNI_EXTENSION);
}

TEST_P(TlsConnectTls13, ConnectShortESNIExtensionEE) {
  EnsureTlsSetup();
  SetupESNI(client_, server_);
  DataBuffer shortNonce;
  auto filter = MakeTlsFilter<TlsExtensionReplacer>(server_,
                                                    ssl_tls13_encrypted_sni_xtn,
                                                    shortNonce);
  filter->EnableDecryption();
  ConnectExpectAlert(client_, illegal_parameter);
  client_->CheckErrorCode(SSL_ERROR_RX_MALFORMED_ESNI_EXTENSION);
}

TEST_P(TlsConnectTls13, ConnectBogusESNIExtensionEE) {
  EnsureTlsSetup();
  SetupESNI(client_, server_);
  const uint8_t bogusNonceBuf[16] = { 0 };
  DataBuffer bogusNonce(bogusNonceBuf, sizeof(bogusNonceBuf));
  auto filter = MakeTlsFilter<TlsExtensionReplacer>(server_,
                                                    ssl_tls13_encrypted_sni_xtn,
                                                    bogusNonce);
  filter->EnableDecryption();
  ConnectExpectAlert(client_, illegal_parameter);
  client_->CheckErrorCode(SSL_ERROR_RX_MALFORMED_ESNI_EXTENSION);
}



}
