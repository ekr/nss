/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "ssl.h"
#include "sslerr.h"
#include "sslproto.h"
#include "pk11pub.h"

extern "C" {
// This is not something that should make you happy.
#include "libssl_internals.h"
}

#include "tls_filter.h"
#include "tls_connect.h"
#include "gtest_utils.h"

namespace nss_test {

// Replaces the client hello with an SSLv2 version once.
class SSLv2ClientHelloFilter : public PacketFilter
{
  public:
    SSLv2ClientHelloFilter(TlsAgent* client, uint16_t version)
        : replaced_(false), client_(client), version_(version), pad_len_(0),
          reported_pad_len_(0), client_random_len_(16), ciphers_(0)
    {
    }

    void
    SetCipherSuites(const std::vector<uint16_t>& ciphers)
    {
        ciphers_ = ciphers;
    }

    // Set a padding length and announce it correctly.
    void
    SetPadding(uint8_t pad_len)
    {
        SetPadding(pad_len, pad_len);
    }

    // Set a padding length and allow to lie about its length.
    void
    SetPadding(uint8_t pad_len, uint8_t reported_pad_len)
    {
        pad_len_ = pad_len;
        reported_pad_len_ = reported_pad_len;
    }

    void
    SetClientRandomLength(uint16_t client_random_len)
    {
        client_random_len_ = client_random_len;
    }

  protected:
    virtual PacketFilter::Action
    Filter(const DataBuffer& input, DataBuffer* output)
    {
        if (replaced_) {
            return KEEP;
        }

        // Replace only the very first packet.
        replaced_ = true;

        // The SSLv2 client hello size.
        size_t packet_len = SSL_HL_CLIENT_HELLO_HBYTES + (ciphers_.size() * 3) +
                            client_random_len_ + pad_len_;

        size_t idx = 0;
        *output = input;
        output->Allocate(packet_len);
        output->Truncate(packet_len);

        // Write record length.
        if (pad_len_ > 0) {
            idx = output->Write(idx, 0x3fff & packet_len, 2);
            idx = output->Write(idx, reported_pad_len_, 1);
        } else {
            idx = output->Write(idx, 0x8000 | packet_len, 2);
        }

        // Remember header length.
        size_t hdr_len = idx;

        // Write client hello.
        idx = output->Write(idx, SSL_MT_CLIENT_HELLO, 1);
        idx = output->Write(idx, version_, 2);

        // Cipher list length.
        idx = output->Write(idx, (ciphers_.size() * 3), 2);

        // Session ID length.
        idx = output->Write(idx, static_cast<uint32_t>(0), 2);

        // ClientRandom length.
        idx = output->Write(idx, client_random_len_, 2);

        // Cipher suites.
        for (auto cipher : ciphers_) {
            idx = output->Write(idx, static_cast<uint32_t>(cipher), 3);
        }

        // Challenge.
        std::vector<uint8_t> challenge(client_random_len_);
        PK11_GenerateRandom(challenge.data(), challenge.size());
        idx = output->Write(idx, challenge.data(), challenge.size());

        // Add padding if any.
        if (pad_len_ > 0) {
            std::vector<uint8_t> pad(pad_len_);
            idx = output->Write(idx, pad.data(), pad.size());
        }

        // Update the client random so that the handshake succeeds.
        SECStatus rv = SSLInt_UpdateSSLv2ClientRandom(client_->ssl_fd(),
                                                      challenge.data(),
                                                      challenge.size(),
                                                      output->data() + hdr_len,
                                                      output->len() - hdr_len);
        EXPECT_EQ(SECSuccess, rv);

        return CHANGE;
    }

  private:
    bool replaced_;
    TlsAgent* client_;
    uint16_t version_;
    uint8_t pad_len_;
    uint8_t reported_pad_len_;
    uint16_t client_random_len_;
    std::vector<uint16_t> ciphers_;
};

class TlsSSLv2ClientHelloTest : public TlsConnectStreamPre13
{
  public:
    void
    SetUp()
    {
        TlsConnectStreamPre13::SetUp();
        filter_ = new SSLv2ClientHelloFilter(client_, version_);
        client_->SetPacketFilter(filter_);
    }

    void
    RequireSafeRenegotiation()
    {
        server_->EnsureTlsSetup();
        SECStatus rv =
            SSL_OptionSet(server_->ssl_fd(), SSL_REQUIRE_SAFE_NEGOTIATION, PR_TRUE);
        EXPECT_EQ(rv, SECSuccess);
    }

    void
    SetAvailableCipherSuite(uint16_t cipher)
    {
        filter_->SetCipherSuites(std::vector<uint16_t>(1, cipher));
    }

    void
    SetAvailableCipherSuites(const std::vector<uint16_t>& ciphers)
    {
        filter_->SetCipherSuites(ciphers);
    }

    void
    SetPadding(uint8_t pad_len)
    {
        filter_->SetPadding(pad_len);
    }

    void
    SetPadding(uint8_t pad_len, uint8_t reported_pad_len)
    {
        filter_->SetPadding(pad_len, reported_pad_len);
    }

    void
    SetClientRandomLength(uint16_t client_random_len)
    {
        filter_->SetClientRandomLength(client_random_len);
    }

  private:
    SSLv2ClientHelloFilter* filter_;
};

// Test negotiating TLS 1.0 - 1.2.
TEST_P(TlsSSLv2ClientHelloTest, Connect) {
  SetAvailableCipherSuite(TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
  Connect();
}

// Test negotiating TLS 1.3.
#ifdef NSS_ENABLE_TLS_1_3
TEST_F(TlsConnectTest, Connect13) {
  SetExpectedVersion(SSL_LIBRARY_VERSION_TLS_1_3);
  client_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_3,
                           SSL_LIBRARY_VERSION_TLS_1_3);
  server_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_3,
                           SSL_LIBRARY_VERSION_TLS_1_3);

  SSLv2ClientHelloFilter* i1 = new SSLv2ClientHelloFilter(
    client_, SSL_LIBRARY_VERSION_TLS_1_3);
  std::vector<uint16_t> cipher_suites =
    { TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 };

  i1->SetCipherSuites(cipher_suites);
  client_->SetPacketFilter(i1);
  ConnectExpectFail();
  EXPECT_EQ(SSL_ERROR_RX_MALFORMED_CLIENT_HELLO, server_->error_code());
}
#endif

// Test negotiating an EC suite.
TEST_P(TlsSSLv2ClientHelloTest, NegotiateECSuite) {
  SetAvailableCipherSuite(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
  Connect();
}

// Test negotiating TLS 1.0 - 1.2 with a padded client hello.
TEST_P(TlsSSLv2ClientHelloTest, AddPadding) {
  SetAvailableCipherSuite(TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
  SetPadding(5);
  Connect();
}

// Invalid SSLv2 client hello padding must fail the handshake.
TEST_P(TlsSSLv2ClientHelloTest, AddErroneousPadding) {
  SetAvailableCipherSuite(TLS_DHE_RSA_WITH_AES_128_CBC_SHA);

  // Append 5 bytes of padding but say it's only 4.
  SetPadding(5, 4);

  ConnectExpectFail();
  EXPECT_EQ(SSL_ERROR_RX_MALFORMED_CLIENT_HELLO, server_->error_code());
}

// Invalid SSLv2 client hello padding must fail the handshake.
TEST_P(TlsSSLv2ClientHelloTest, AddErroneousPadding2) {
  SetAvailableCipherSuite(TLS_DHE_RSA_WITH_AES_128_CBC_SHA);

  // Append 5 bytes of padding but say it's 6.
  SetPadding(5, 6);

  ConnectExpectFail();
  EXPECT_EQ(SSL_ERROR_RX_MALFORMED_CLIENT_HELLO, server_->error_code());
}

// Wrong amount of bytes for the ClientRandom must fail the handshake.
TEST_P(TlsSSLv2ClientHelloTest, SmallClientRandom) {
  SetAvailableCipherSuite(TLS_DHE_RSA_WITH_AES_128_CBC_SHA);

  // Send a ClientRandom that's too small.
  SetClientRandomLength(15);

  ConnectExpectFail();
  EXPECT_EQ(SSL_ERROR_RX_MALFORMED_CLIENT_HELLO, server_->error_code());
}

// Test sending the maximum accepted number of ClientRandom bytes.
TEST_P(TlsSSLv2ClientHelloTest, MaxClientRandom) {
  SetAvailableCipherSuite(TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
  SetClientRandomLength(32);
  Connect();
}

// Wrong amount of bytes for the ClientRandom must fail the handshake.
TEST_P(TlsSSLv2ClientHelloTest, BigClientRandom) {
  SetAvailableCipherSuite(TLS_DHE_RSA_WITH_AES_128_CBC_SHA);

  // Send a ClientRandom that's too big.
  SetClientRandomLength(33);

  ConnectExpectFail();
  EXPECT_EQ(SSL_ERROR_RX_MALFORMED_CLIENT_HELLO, server_->error_code());
}

// Connection must fail if we require safe renegotiation but the client doesn't
// include TLS_EMPTY_RENEGOTIATION_INFO_SCSV in the list of cipher suites.
TEST_P(TlsSSLv2ClientHelloTest, RequireSafeRenegotiation) {
  RequireSafeRenegotiation();
  SetAvailableCipherSuite(TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
  ConnectExpectFail();
  EXPECT_EQ(SSL_ERROR_UNSAFE_NEGOTIATION, server_->error_code());
}

// Connection must succeed when requiring safe renegotiation and the client
// includes TLS_EMPTY_RENEGOTIATION_INFO_SCSV in the list of cipher suites.
TEST_P(TlsSSLv2ClientHelloTest, RequireSafeRenegotiationWithSCSV) {
  RequireSafeRenegotiation();
  std::vector<uint16_t> cipher_suites =
    { TLS_DHE_RSA_WITH_AES_128_CBC_SHA, TLS_EMPTY_RENEGOTIATION_INFO_SCSV };
  SetAvailableCipherSuites(cipher_suites);
  Connect();
}

// Connect to the server with TLS 1.1, signalling that this is a fallback from
// a higher version. As the server doesn't support anything higher than TLS 1.1
// it must accept the connection.
TEST_F(TlsConnectTest, FallbackSCSV) {
  SetExpectedVersion(SSL_LIBRARY_VERSION_TLS_1_1);
  client_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_1,
                           SSL_LIBRARY_VERSION_TLS_1_1);
  server_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_1,
                           SSL_LIBRARY_VERSION_TLS_1_1);

  SSLv2ClientHelloFilter* i1 = new SSLv2ClientHelloFilter(
    client_, SSL_LIBRARY_VERSION_TLS_1_1);
  std::vector<uint16_t> cipher_suites =
    { TLS_DHE_RSA_WITH_AES_128_CBC_SHA, TLS_FALLBACK_SCSV };

  i1->SetCipherSuites(cipher_suites);
  client_->SetPacketFilter(i1);
  Connect();
}

// Connect to the server with TLS 1.1, signalling that this is a fallback from
// a higher version. As the server supports TLS 1.2 though it must reject the
// connection due to a possible downgrade attack.
TEST_F(TlsConnectTest, InappropriateFallbackSCSV) {
  SetExpectedVersion(SSL_LIBRARY_VERSION_TLS_1_1);
  client_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_1,
                           SSL_LIBRARY_VERSION_TLS_1_1);
  server_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_1,
                           SSL_LIBRARY_VERSION_TLS_1_2);

  SSLv2ClientHelloFilter* i1 = new SSLv2ClientHelloFilter(
    client_, SSL_LIBRARY_VERSION_TLS_1_1);
  std::vector<uint16_t> cipher_suites =
    { TLS_DHE_RSA_WITH_AES_128_CBC_SHA, TLS_FALLBACK_SCSV };

  i1->SetCipherSuites(cipher_suites);
  client_->SetPacketFilter(i1);
  ConnectExpectFail();
  EXPECT_EQ(SSL_ERROR_INAPPROPRIATE_FALLBACK_ALERT, server_->error_code());
}

INSTANTIATE_TEST_CASE_P(VersionsStream10Pre13, TlsSSLv2ClientHelloTest,
                        TlsConnectTestBase::kTlsV10);
INSTANTIATE_TEST_CASE_P(VersionsStreamPre13, TlsSSLv2ClientHelloTest,
                        TlsConnectTestBase::kTlsV11V12);

}  // namespace nss_test
