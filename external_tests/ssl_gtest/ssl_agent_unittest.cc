/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "ssl.h"
#include "sslerr.h"
#include "sslproto.h"

#include <memory>

#include "databuffer.h"
#include "tls_agent.h"
#include "tls_connect.h"
#include "tls_filter.h"
#include "tls_parser.h"

namespace nss_test {

#ifdef NSS_ENABLE_TLS_1_3
// This is a 1-RTT ClientHello with ECDHE and DHE.
const static uint8_t kCannedTls13ClientHello[] = {
  0x01, 0x00, 0x01, 0xfc, 0x03, 0x04, 0x77, 0x5c,
  0x3a, 0xd8, 0x3f, 0x43, 0x63, 0x98, 0xfa, 0x68,
  0xfb, 0x01, 0x39, 0xff, 0x7c, 0x1a, 0x51, 0xa7,
  0x92, 0xda, 0x97, 0xf5, 0x15, 0x78, 0xb3, 0xbb,
  0x26, 0xa7, 0xed, 0x6f, 0x69, 0x71, 0x00, 0x00,
  0x2a, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc,
  0xa8, 0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x13, 0xc0,
  0x14, 0x00, 0x9e, 0xcc, 0xaa, 0x00, 0x33, 0x00,
  0x32, 0x00, 0x39, 0x00, 0x38, 0x00, 0x16, 0x00,
  0x13, 0x00, 0x2f, 0x00, 0x35, 0x00, 0x0a, 0x00,
  0x05, 0x00, 0x04, 0x01, 0x00, 0x01, 0xa9, 0x00,
  0x00, 0x00, 0x0b, 0x00, 0x09, 0x00, 0x00, 0x06,
  0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0xff, 0x01,
  0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x0a, 0x00,
  0x08, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01,
  0x00, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0xff,
  0x02, 0x00, 0x02, 0x00, 0x0d, 0x00, 0x28, 0x01,
  0x4b, 0x01, 0x49, 0x00, 0x17, 0x00, 0x41, 0x04,
  0xbf, 0x31, 0xb4, 0x29, 0x96, 0xf4, 0xe6, 0x4a,
  0xe3, 0xea, 0x87, 0x05, 0x38, 0x0e, 0x68, 0x02,
  0xbc, 0x4a, 0x5d, 0x90, 0xed, 0xe7, 0xaa, 0x8e,
  0xb8, 0x42, 0x84, 0xaa, 0x3a, 0x4f, 0x2b, 0xe3,
  0x52, 0x9a, 0x9a, 0x76, 0xab, 0xf8, 0x2e, 0x59,
  0xea, 0xcd, 0x2b, 0x2f, 0x03, 0x18, 0xd2, 0x0c,
  0xc9, 0x07, 0x15, 0xca, 0xe6, 0x61, 0xf7, 0x79,
  0x9f, 0xfe, 0xc5, 0x10, 0x40, 0x9e, 0x38, 0x33,
  0x01, 0x00, 0x01, 0x00, 0xd8, 0x80, 0x1f, 0x06,
  0x9a, 0xbb, 0xf7, 0xbb, 0xd4, 0x5c, 0x75, 0x1d,
  0x8e, 0x09, 0x27, 0xad, 0x08, 0xb8, 0x16, 0x0f,
  0x4f, 0x50, 0x79, 0xe1, 0x7e, 0xd4, 0x3b, 0xc0,
  0x57, 0xcc, 0x00, 0x5e, 0x28, 0xd8, 0xb3, 0x16,
  0x7f, 0x36, 0x48, 0x75, 0x8d, 0x03, 0xa4, 0x71,
  0x86, 0x06, 0xf0, 0xe7, 0x57, 0x47, 0x35, 0xf0,
  0x04, 0xfb, 0xf7, 0x6c, 0x7a, 0xdd, 0x05, 0x93,
  0x53, 0x16, 0x12, 0x49, 0xbe, 0x35, 0x67, 0x47,
  0x6e, 0x3a, 0x91, 0xef, 0x50, 0x09, 0x14, 0x98,
  0x8b, 0x83, 0xc4, 0x62, 0x77, 0xf3, 0x57, 0x53,
  0x3f, 0xf4, 0x82, 0xc0, 0x70, 0x25, 0x19, 0x9d,
  0x93, 0xe2, 0xb9, 0x7b, 0xb4, 0x83, 0x31, 0xef,
  0xd8, 0x3b, 0xd5, 0x25, 0x70, 0x64, 0x29, 0xa2,
  0xc2, 0xc5, 0x73, 0x9a, 0xfe, 0x27, 0xca, 0xc0,
  0x55, 0x34, 0x91, 0x95, 0x05, 0xbf, 0x5e, 0x54,
  0x4d, 0x95, 0x43, 0x3d, 0x54, 0x6a, 0x89, 0x0b,
  0x5e, 0xab, 0x08, 0x7b, 0xf8, 0x38, 0x0a, 0x56,
  0x51, 0x9d, 0xbc, 0xdd, 0x46, 0xa9, 0xfc, 0x95,
  0xe9, 0x75, 0x1c, 0xc8, 0x18, 0x7f, 0xed, 0xa9,
  0xca, 0xb6, 0x5e, 0x77, 0x63, 0x33, 0xb1, 0xb5,
  0x68, 0xce, 0xa5, 0x98, 0xec, 0x8c, 0x34, 0x98,
  0x1c, 0xa9, 0xa5, 0x84, 0xec, 0xe6, 0xba, 0x0b,
  0x11, 0xbf, 0x40, 0xa5, 0xf0, 0x3c, 0xd5, 0xd3,
  0xac, 0x2f, 0x46, 0xed, 0xab, 0xc0, 0xc1, 0x78,
  0x3f, 0x18, 0x64, 0x5b, 0xff, 0x31, 0xeb, 0x74,
  0x06, 0x92, 0x42, 0x1e, 0x90, 0xf7, 0xea, 0xa5,
  0x02, 0x33, 0x8e, 0x01, 0xe3, 0xfa, 0x70, 0x82,
  0xe5, 0xe7, 0x67, 0x8b, 0x96, 0x20, 0x13, 0x2e,
  0x65, 0x86, 0xab, 0x28, 0xc8, 0x1b, 0xfe, 0xb4,
  0x98, 0xed, 0xa4, 0xa0, 0xee, 0xf9, 0x53, 0x74,
  0x30, 0xac, 0x79, 0x2d, 0xf2, 0x92, 0xd0, 0x5e,
  0x10, 0xd7, 0xb9, 0x41, 0x00, 0x0d, 0x00, 0x18,
  0x00, 0x16, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01,
  0x02, 0x01, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03,
  0x02, 0x03, 0x05, 0x02, 0x04, 0x02, 0x02, 0x02,
  0x00, 0x15, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

const static uint8_t kCannedTls13ServerHello[] = {
  0x03, 0x04, 0xe9, 0x01, 0xa0, 0x81, 0x37, 0x97,
  0xaa, 0x8c, 0x7e, 0x21, 0x1c, 0x66, 0x3f, 0xa4,
  0x0f, 0x4d, 0x74, 0x7a, 0xcd, 0x4b, 0xe1, 0x7f,
  0x37, 0x85, 0x14, 0xb5, 0x7e, 0x30, 0x15, 0x91,
  0xdf, 0x18, 0xc0, 0x2f, 0x00, 0x49, 0x00, 0x28,
  0x00, 0x45, 0x00, 0x17, 0x00, 0x41, 0x04, 0x1a,
  0x53, 0x9b, 0x39, 0xe6, 0xda, 0x66, 0xfc, 0x8a,
  0x75, 0x68, 0xb7, 0x73, 0xc7, 0x21, 0x1f, 0x01,
  0x04, 0x54, 0xb4, 0x99, 0x1f, 0x0b, 0x7e, 0xea,
  0x95, 0xec, 0x78, 0x5c, 0x37, 0x7c, 0x31, 0x56,
  0x04, 0xc8, 0xbf, 0x79, 0x47, 0x56, 0xb9, 0x87,
  0x06, 0xc1, 0xfc, 0x63, 0x09, 0x5d, 0xfc, 0x1a,
  0x9e, 0x2b, 0xb9, 0xca, 0xdb, 0x0e, 0x10, 0xec,
  0xd5, 0x95, 0x0d, 0x0a, 0x5e, 0x3c, 0xf7
};

static const char *k0RttData = "ABCDEF";
#endif

TEST_P(TlsAgentTest, EarlyFinished) {
  DataBuffer buffer;
  MakeTrivialHandshakeRecord(kTlsHandshakeFinished, 0, &buffer);
  ProcessMessage(buffer, TlsAgent::STATE_ERROR,
                 SSL_ERROR_RX_UNEXPECTED_FINISHED);
}

TEST_P(TlsAgentTest, EarlyCertificateVerify) {
  DataBuffer buffer;
  MakeTrivialHandshakeRecord(kTlsHandshakeCertificateVerify, 0, &buffer);
  ProcessMessage(buffer, TlsAgent::STATE_ERROR,
                 SSL_ERROR_RX_UNEXPECTED_CERT_VERIFY);
}

#ifdef NSS_ENABLE_TLS_1_3
TEST_P(TlsAgentTestClient, CannedHello) {
  DataBuffer buffer;
  EnsureInit();
  agent_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_3,
                          SSL_LIBRARY_VERSION_TLS_1_3);
  DataBuffer server_hello_inner(kCannedTls13ServerHello,
                                sizeof(kCannedTls13ServerHello));
  uint16_t wire_version = mode_ == STREAM ?
      SSL_LIBRARY_VERSION_TLS_1_3:
      TlsVersionToDtlsVersion(SSL_LIBRARY_VERSION_TLS_1_3);
  server_hello_inner.Write(0, wire_version, 2);
  DataBuffer server_hello;
  MakeHandshakeMessage(kTlsHandshakeServerHello,
                       server_hello_inner.data(),
                       server_hello_inner.len(),
                       &server_hello);
  MakeRecord(kTlsHandshakeType, SSL_LIBRARY_VERSION_TLS_1_3,
             server_hello.data(), server_hello.len(), &buffer);
  ProcessMessage(buffer, TlsAgent::STATE_CONNECTING);
}


TEST_P(TlsAgentTestClient, EncryptedExtensionsInClear) {
  DataBuffer buffer;
  DataBuffer server_hello_inner(kCannedTls13ServerHello,
                                sizeof(kCannedTls13ServerHello));
  server_hello_inner.Write(0,
                           mode_ == STREAM ?
                           SSL_LIBRARY_VERSION_TLS_1_3:
                           TlsVersionToDtlsVersion(
                               SSL_LIBRARY_VERSION_TLS_1_3),
                           2);
  DataBuffer server_hello;
  MakeHandshakeMessage(kTlsHandshakeServerHello,
                       server_hello_inner.data(),
                       server_hello_inner.len(),
                       &server_hello);
  DataBuffer encrypted_extensions;
  MakeHandshakeMessage(kTlsHandshakeEncryptedExtensions, nullptr, 0,
                       &encrypted_extensions, 1);
  server_hello.Append(encrypted_extensions);
  MakeRecord(kTlsHandshakeType,
             SSL_LIBRARY_VERSION_TLS_1_3,
             server_hello.data(),
             server_hello.len(), &buffer);
  EnsureInit();
  agent_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_3,
                          SSL_LIBRARY_VERSION_TLS_1_3);
  ProcessMessage(buffer, TlsAgent::STATE_ERROR,
                 SSL_ERROR_RX_UNEXPECTED_HANDSHAKE);
}

TEST_F(TlsAgentStreamTestClient, EncryptedExtensionsInClearTwoPieces) {
  DataBuffer buffer;
  DataBuffer buffer2;
  DataBuffer server_hello_inner(kCannedTls13ServerHello,
                                sizeof(kCannedTls13ServerHello));
  server_hello_inner.Write(0, SSL_LIBRARY_VERSION_TLS_1_3, 2);
  DataBuffer server_hello;
  MakeHandshakeMessage(kTlsHandshakeServerHello,
                       server_hello_inner.data(),
                       server_hello_inner.len(),
                       &server_hello);
  DataBuffer encrypted_extensions;
  MakeHandshakeMessage(kTlsHandshakeEncryptedExtensions, nullptr, 0,
                       &encrypted_extensions, 1);
  server_hello.Append(encrypted_extensions);
  MakeRecord(kTlsHandshakeType,
             SSL_LIBRARY_VERSION_TLS_1_3,
             server_hello.data(), 20,
             &buffer);

  MakeRecord(kTlsHandshakeType,
             SSL_LIBRARY_VERSION_TLS_1_3,
             server_hello.data() + 20,
             server_hello.len() - 20, &buffer2);

  EnsureInit();
  agent_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_3,
                          SSL_LIBRARY_VERSION_TLS_1_3);
  ProcessMessage(buffer, TlsAgent::STATE_CONNECTING);
  ProcessMessage(buffer2, TlsAgent::STATE_ERROR,
                 SSL_ERROR_RX_UNEXPECTED_HANDSHAKE);
}


TEST_F(TlsAgentDgramTestClient, EncryptedExtensionsInClearTwoPieces) {
  DataBuffer buffer;
  DataBuffer buffer2;
  DataBuffer server_hello_inner(kCannedTls13ServerHello,
                                sizeof(kCannedTls13ServerHello));
  server_hello_inner.Write(
      0, TlsVersionToDtlsVersion(SSL_LIBRARY_VERSION_TLS_1_3), 2);
  DataBuffer server_hello_frag1;
  MakeHandshakeMessageFragment(kTlsHandshakeServerHello,
                       server_hello_inner.data(),
                       server_hello_inner.len(),
                       &server_hello_frag1, 0,
                       0, 20);
  DataBuffer server_hello_frag2;
  MakeHandshakeMessageFragment(kTlsHandshakeServerHello,
                       server_hello_inner.data() + 20,
                       server_hello_inner.len(), &server_hello_frag2, 0,
                       20, server_hello_inner.len() - 20);
  DataBuffer encrypted_extensions;
  MakeHandshakeMessage(kTlsHandshakeEncryptedExtensions, nullptr, 0,
                       &encrypted_extensions, 1);
  server_hello_frag2.Append(encrypted_extensions);
  MakeRecord(kTlsHandshakeType,
             SSL_LIBRARY_VERSION_TLS_1_3,
             server_hello_frag1.data(), server_hello_frag1.len(),
             &buffer);

  MakeRecord(kTlsHandshakeType,
             SSL_LIBRARY_VERSION_TLS_1_3,
             server_hello_frag2.data(), server_hello_frag2.len(),
             &buffer2, 1);

  EnsureInit();
  agent_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_3,
                          SSL_LIBRARY_VERSION_TLS_1_3);
  ProcessMessage(buffer, TlsAgent::STATE_CONNECTING);
  ProcessMessage(buffer2, TlsAgent::STATE_ERROR,
                 SSL_ERROR_RX_UNEXPECTED_HANDSHAKE);
}

TEST_F(TlsAgentStreamTestClient, Set0RttOptionThenWrite) {
  EnsureInit();
  agent_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_1,
                          SSL_LIBRARY_VERSION_TLS_1_3);
  agent_->StartConnect();
  agent_->Set0RttEnabled(true);
  auto filter =
      new TlsInspectorRecordHandshakeMessage(kTlsHandshakeClientHello);
  agent_->SetPacketFilter(filter);
  PRInt32 rv = PR_Write(agent_->ssl_fd(),
                        k0RttData, strlen(k0RttData));
  EXPECT_EQ(-1, rv);
  int32_t err = PORT_GetError();
  EXPECT_EQ(PR_WOULD_BLOCK_ERROR, err);
  EXPECT_LT(0UL, filter->buffer().len());
}

TEST_F(TlsAgentStreamTestClient, Set0RttOptionThenRead) {
  EnsureInit();
  agent_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_1,
                          SSL_LIBRARY_VERSION_TLS_1_3);
  agent_->StartConnect();
  agent_->Set0RttEnabled(true);
  DataBuffer buffer;
  MakeRecord(kTlsApplicationDataType, SSL_LIBRARY_VERSION_TLS_1_3,
             reinterpret_cast<const uint8_t *>(k0RttData),
             strlen(k0RttData), &buffer);
  ProcessMessage(buffer, TlsAgent::STATE_ERROR,
                 SSL_ERROR_RX_UNEXPECTED_APPLICATION_DATA);
}

// The server is allowing 0-RTT but the client doesn't offer it,
// so trial decryption isn't engaged and 0-RTT messages cause
// an error.
TEST_F(TlsAgentStreamTestServer, Set0RttOptionClientHelloThenRead) {
  EnsureInit();
  agent_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_1,
                          SSL_LIBRARY_VERSION_TLS_1_3);
  agent_->StartConnect();
  agent_->Set0RttEnabled(true);
  DataBuffer buffer;
  MakeRecord(kTlsHandshakeType, SSL_LIBRARY_VERSION_TLS_1_3,
             kCannedTls13ClientHello, sizeof(kCannedTls13ClientHello),
             &buffer);
  ProcessMessage(buffer, TlsAgent::STATE_CONNECTING);
  MakeRecord(kTlsApplicationDataType, SSL_LIBRARY_VERSION_TLS_1_3,
             reinterpret_cast<const uint8_t *>(k0RttData),
             strlen(k0RttData), &buffer);
  ProcessMessage(buffer, TlsAgent::STATE_ERROR,
                 SSL_ERROR_BAD_MAC_READ);
}

TEST_F(TlsAgentStreamTestServer, CannedBogoHello) {
  uint8_t kBogoTls13ClientHello[]={
    0x01, 0x00, 0x02, 0x0d, 0x03, 0x04, 0x8a, 0x5d,
    0x5c, 0xc4, 0x62, 0xf9, 0xef, 0xd1, 0x9a, 0xaf,
    0x97, 0x91, 0xfc, 0x6e, 0xb6, 0xa4, 0x1a, 0xc6,
    0xbd, 0xa5, 0x8e, 0xa5, 0x8f, 0x36, 0x77, 0x29,
    0x9e, 0xa3, 0x9c, 0xa3, 0xae, 0x39, 0x00, 0x00,
    0x50, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0x14, 0xcc,
    0x13, 0xc0, 0x2f, 0xc0, 0x2b, 0xc0, 0x30, 0xc0,
    0x2c, 0xc0, 0x11, 0xc0, 0x07, 0xc0, 0x27, 0xc0,
    0x23, 0xc0, 0x13, 0xc0, 0x09, 0xc0, 0x28, 0xc0,
    0x24, 0xc0, 0x14, 0xc0, 0x0a, 0x16, 0xb7, 0x16,
    0xb8, 0x16, 0xb9, 0x16, 0xba, 0x00, 0x9e, 0x00,
    0x9f, 0x00, 0x67, 0x00, 0x6b, 0x00, 0x33, 0x00,
    0x39, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x05, 0x00,
    0x04, 0x00, 0x3c, 0x00, 0x3d, 0x00, 0x2f, 0x00,
    0x35, 0xc0, 0x12, 0x00, 0x16, 0x00, 0x0a, 0x00,
    0x02, 0x01, 0x00, 0x01, 0x94, 0xff, 0x02, 0x00,
    0x02, 0x00, 0x0d, 0x00, 0x0a, 0x00, 0x0a, 0x00,
    0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00,
    0x19, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00,
    0x28, 0x01, 0x59, 0x01, 0x57, 0x00, 0x1d, 0x00,
    0x20, 0xe3, 0x0f, 0x4c, 0x07, 0xe1, 0x74, 0x70,
    0x05, 0x6f, 0xe9, 0xe9, 0xd6, 0x5c, 0x3c, 0x18,
    0xce, 0x57, 0xd0, 0xde, 0xec, 0x9a, 0x5c, 0xac,
    0x6d, 0x93, 0x14, 0xbe, 0x92, 0x5c, 0xdd, 0x50,
    0x39, 0x00, 0x17, 0x00, 0x41, 0x04, 0xc4, 0x21,
    0xe4, 0xa3, 0x39, 0x65, 0x4d, 0x5e, 0x6a, 0x7b,
    0xe5, 0xd4, 0x87, 0x64, 0x18, 0xb3, 0xec, 0x64,
    0xb3, 0x48, 0x1c, 0xeb, 0xac, 0xd3, 0x94, 0x3f,
    0xfe, 0x88, 0x80, 0xe5, 0xeb, 0x9f, 0x68, 0x7c,
    0x36, 0xf0, 0x38, 0x05, 0x82, 0x54, 0x3b, 0x58,
    0xb5, 0x79, 0xac, 0x42, 0x9a, 0x04, 0x4b, 0xdc,
    0xf6, 0x0c, 0x0d, 0x1b, 0xe2, 0x36, 0xa9, 0xac,
    0xb5, 0x0f, 0xdb, 0xc6, 0x38, 0xfe, 0x00, 0x18,
    0x00, 0x61, 0x04, 0x30, 0x1a, 0x8e, 0x55, 0xe9,
    0x74, 0xbb, 0x24, 0x09, 0xbc, 0x63, 0x79, 0xac,
    0xa8, 0xeb, 0xd0, 0x03, 0xda, 0xec, 0x28, 0x83,
    0x55, 0xf8, 0x77, 0xdd, 0xd7, 0xf8, 0x33, 0xeb,
    0x67, 0xce, 0x08, 0x85, 0x18, 0xb1, 0xa9, 0x69,
    0xa3, 0x35, 0x41, 0x23, 0x97, 0xe0, 0xe1, 0xbd,
    0x49, 0x26, 0x54, 0xd3, 0x11, 0xb5, 0x87, 0x50,
    0x6b, 0x8a, 0x71, 0x5a, 0x91, 0x82, 0x44, 0x25,
    0xcc, 0x0a, 0x04, 0xa1, 0xe7, 0x8c, 0x26, 0xf5,
    0x10, 0x47, 0xc6, 0xcd, 0x16, 0x9e, 0x0f, 0xcd,
    0xb1, 0xfb, 0xf9, 0x84, 0x40, 0xb5, 0x11, 0xb9,
    0xa8, 0xb2, 0x75, 0xc4, 0xab, 0x07, 0x1b, 0xb4,
    0xda, 0xf3, 0xd2, 0x00, 0x19, 0x00, 0x85, 0x04,
    0x00, 0xea, 0x62, 0xee, 0x36, 0xb4, 0xa3, 0x5e,
    0xd5, 0x78, 0xd8, 0xe4, 0xb7, 0xa1, 0xcd, 0x4f,
    0x0c, 0xc6, 0x1f, 0xb1, 0xfb, 0x2d, 0xaf, 0x2a,
    0x90, 0xc0, 0x6d, 0x91, 0xd8, 0x62, 0x05, 0xd8,
    0x85, 0xec, 0x76, 0x96, 0x5e, 0xbc, 0xea, 0x62,
    0xaa, 0x22, 0x2e, 0x7f, 0x98, 0xc0, 0x73, 0x44,
    0x55, 0xb8, 0xeb, 0x2c, 0x0b, 0x49, 0xd6, 0xe4,
    0x26, 0x9a, 0x47, 0x14, 0xaa, 0x59, 0x73, 0xb5,
    0x89, 0xe9, 0x01, 0xac, 0xc7, 0x71, 0x3b, 0x85,
    0x00, 0x05, 0x03, 0x92, 0x47, 0x9e, 0xe7, 0x23,
    0x8c, 0xeb, 0xc3, 0x62, 0xe7, 0x30, 0xe0, 0x3f,
    0xf4, 0x6f, 0xdc, 0x7d, 0x0e, 0x71, 0xbf, 0xc1,
    0x5a, 0x89, 0x22, 0x31, 0x26, 0x22, 0x5a, 0x86,
    0x29, 0xe2, 0x2a, 0x59, 0x4d, 0x22, 0xde, 0xa1,
    0x75, 0x36, 0x7d, 0x8c, 0xa9, 0xfd, 0xc9, 0x7b,
    0x63, 0x74, 0xcc, 0x6e, 0xce, 0x28, 0x6e, 0x54,
    0x11, 0x08, 0x33, 0x1b, 0x00, 0x0d, 0x00, 0x0c,
    0x00, 0x0a, 0x07, 0x00, 0x04, 0x01, 0x04, 0x03,
    0x02, 0x01, 0x02, 0x03, 0xff, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x12, 0x00,
    0x00
  };
  DataBuffer buffer;
  EnsureInit();
  agent_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_3,
                          SSL_LIBRARY_VERSION_TLS_1_3);
  MakeRecord(kTlsHandshakeType, SSL_LIBRARY_VERSION_TLS_1_3,
             kBogoTls13ClientHello, sizeof(kBogoTls13ClientHello), &buffer);
  ProcessMessage(buffer, TlsAgent::STATE_CONNECTING);
}

#endif

INSTANTIATE_TEST_CASE_P(AgentTests, TlsAgentTest,
                        ::testing::Combine(
                             TlsAgentTestBase::kTlsRolesAll,
                             TlsConnectTestBase::kTlsModesStream));
#ifdef NSS_ENABLE_TLS_1_3
INSTANTIATE_TEST_CASE_P(ClientTests, TlsAgentTestClient,
                        TlsConnectTestBase::kTlsModesAll);
#endif
} // namespace nss_test
