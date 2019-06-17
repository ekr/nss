/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <cstdlib>
#include <iostream>
#include <unistd.h>
#include <map>
#include <memory>

#include "nspr.h"
#include "nss.h"
#include "prio.h"
#include "prnetdb.h"
#include "secerr.h"
#include "ssl.h"
#include "ssl3prot.h"
#include "sslerr.h"
#include "sslproto.h"

#include "udp_socket.h"
#include "nsskeys.h"

namespace nss_test {

struct Config {
  std::string key_file;
  std::string cert_file;
};

class Agent {
 public:
  Agent(PRFileDesc* fd, const Config& cfg, const PRNetAddr& peer) :
      cfg_(cfg),
      socket_(new UdpSocket(fd, peer)),
      pr_fd_(socket_->CreateFD()),
      ssl_fd_(nullptr),
      cert_(nullptr),
      key_(nullptr) {
  }

  bool Init() {
    ssl_fd_.reset(DTLS_ImportFD(NULL, pr_fd_.get()));
    if (!ssl_fd_) {
      std::cerr << "Couldn't import socket\n";
      return false;
    }
    if (!SetupKeys()) {
      std::cerr << "Couldn't set up keys/certs\n";
      return false;
    }

    auto rv = SSL_OptionSet(ssl_fd_.get(), SSL_NO_CACHE, PR_TRUE);
    if (rv != SECSuccess) return false;

    const uint8_t ekt_ciphers[] = {EKT_AESKW_128, EKT_AESKW_256};
    rv = SSL_SetEKTCiphers(ssl_fd_.get(), ekt_ciphers, PR_ARRAY_SIZE(ekt_ciphers));
    if (rv != SECSuccess) return false;

    const SSLEKTKey ektKey = {
      {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x05, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      },
      16,
      {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x15, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
      },
      24,
      0xA0A0,
      0xB0B0B0
    };
    rv = SSL_SetEKTKey(ssl_fd_.get(), &ektKey);
    if (rv != SECSuccess) return false;

    const uint16_t srtp_ciphers[] = {SRTP_AEAD_AES_128_GCM_DOUBLE,
                                     SRTP_AEAD_AES_256_GCM_DOUBLE};
    rv = SSL_SetSRTPCiphers(ssl_fd_.get(), srtp_ciphers, PR_ARRAY_SIZE(srtp_ciphers));
    if (rv != SECSuccess) return false;

    rv = SSL_ResetHandshake(ssl_fd_.get(), PR_TRUE);
    if (rv != SECSuccess) return false;

    return true;
  }


  // Create the SRTP keys packet to send out.
  //
  // I am using the ad-hoc structure
  //
  // struct {
  //   uint8 marker = 0xff;
  //   uint16 profile;
  //   opaque client_write_key<0..2^8-1>;
  //   opaque server_write_key<0..2^8-1>;
  //   opaque master_salt<0..2^8-1>;
  // }
  bool MarshalSRTPKeys(const SSLEKTKey& key, DataBuffer* buffer) {
    size_t index = 0;
    size_t fullKeySize = 0;
    size_t halfKeySize = 0;
    size_t fullSaltSize = key.srtpMasterSaltLength;
    size_t halfSaltSize = fullSaltSize / 2;

    // Check which SRTP cipher is in use
    uint16_t cipher;
    auto rv = SSL_GetSRTPCipher(ssl_fd_.get(), &cipher);
    if (rv != SECSuccess) {
      return false;
    }

    switch (cipher) {
      case SRTP_AEAD_AES_128_GCM:
        fullKeySize = 16;
        halfKeySize = 16;
        break;
      case SRTP_AEAD_AES_128_GCM_DOUBLE:
        fullKeySize = 32;
        halfKeySize = 16;
        break;
      case SRTP_AEAD_AES_256_GCM:
        fullKeySize = 32;
        halfKeySize = 32;
        break;
      case SRTP_AEAD_AES_256_GCM_DOUBLE:
        fullKeySize = 64;
        halfKeySize = 32;
        break;
      default:
        return false;
    }

    // Extract the client and server keys
    //
    // Recall initial extract has the form:
    //   client_k_i | client_k_o | server_k_i | server_k_o |
    //   client_s_i | client_s_o | server_s_i | server_s_o
    DataBuffer everything;
    const std::string label = "EXTRACTOR-dtls_srtp";
    const size_t exportSize = 2 * (fullKeySize + fullSaltSize);
    everything.Allocate(exportSize);
    rv = SSL_ExportKeyingMaterial(ssl_fd_.get(),
                                  label.c_str(), label.size(), false,
                                  nullptr, 0,
                                  everything.data(), everything.len());
    if (rv != SECSuccess) {
      return false;
    }

    DataBuffer nothing;
    DataBuffer clientWriteKey(everything);
    DataBuffer serverWriteKey(everything);

    // Splice() won't work unless this has a non-null buffer
    nothing.Allocate(1);
    nothing.Truncate(0);
    clientWriteKey.Splice(nothing, 0, halfKeySize);
    clientWriteKey.Truncate(halfKeySize);
    serverWriteKey.Splice(nothing, 0, fullKeySize + halfKeySize);
    serverWriteKey.Truncate(halfKeySize);

    // Encode the packet
    index = buffer->Write(index, 0xff, 1);
    index = buffer->Write(index, cipher, 2);
    index = buffer->Write(index, clientWriteKey.len(), 1);
    index = buffer->Write(index, clientWriteKey.data(), clientWriteKey.len());
    index = buffer->Write(index, serverWriteKey.len(), 1);
    index = buffer->Write(index, serverWriteKey.data(), serverWriteKey.len());
    index = buffer->Write(index, halfSaltSize, 1);
    index = buffer->Write(index, key.srtpMasterSalt + halfSaltSize, halfSaltSize);
    return true;
  }

  bool NewData(const uint8_t* buf, size_t len) {
    DataBuffer db(buf, len);

    socket_->PacketReceived(db);

    auto rv = SSL_ForceHandshake(ssl_fd_.get());
    if (rv == SECSuccess) {
      std::cout << "DTLS connected\n";

      uint8_t cipher;
      rv = SSL_GetEKTCipher(ssl_fd_.get(), &cipher);
      if (rv != SECSuccess) {
        return false;
      }

      SSLEKTKey ektKey;
      rv = SSL_GetEKTKey(ssl_fd_.get(), &ektKey);
      if (rv != SECSuccess) {
        return false;
      }

      std::cout << "EKT cipher " << static_cast<int>(cipher) << std::endl;

      uint16_t srtp;
      rv = SSL_GetSRTPCipher(ssl_fd_.get(), &srtp);
      if (rv != SECSuccess) {
        return false;
      }

      std::cout << "SRTP cipher: " << srtp << std::endl;

      DataBuffer d;
      if (!MarshalSRTPKeys(ektKey, &d)) {
        std::cerr << "Couldn't marshal SRTP keys\n";
        return false;
      }

      auto n = socket_->Write(ssl_fd_.get(), d.data(), d.len());
      if (static_cast<size_t>(n) != d.len()) {
        std::cerr << "Couldn't write SRTP keys\n";
        return false;
      }
      std::cout << "Wrote SRTP keys\n";
    } else {
      auto err = PR_GetError();
      if (err == PR_WOULD_BLOCK_ERROR) {
        std::cout << "Would have blocked\n";
      } else {
        std::cout << "Error: " << PORT_ErrorToName(err) << std::endl;
        return false;
      }
    }


    return true;
  }

  bool SetupKeys() {
    SECStatus rv;

    cert_ = ReadCertificate(cfg_.cert_file);
    if (!cert_) return false;


    key_ = ReadPrivateKey(cfg_.key_file);
    if (!key_) return false;

    // Server
    rv = SSL_ConfigServerCert(ssl_fd_.get(), cert_, key_, nullptr, 0);
    if (rv != SECSuccess) {
      std::cerr << "Couldn't configure server cert\n";
      return false;
    }

    return true;
  }

  ~Agent() {
    if (key_) {
      SECKEY_DestroyPrivateKey(key_);
    }

    if (cert_) {
      CERT_DestroyCertificate(cert_);
    }
  }
 private:
  const Config& cfg_;
  std::unique_ptr<UdpSocket> socket_;
  ScopedPRFileDesc pr_fd_;
  ScopedPRFileDesc ssl_fd_;
  CERTCertificate* cert_;
  SECKEYPrivateKey* key_;
};

class Server {
 public:
  Server(const Config& cfg)
      : cfg_(cfg),
        pr_fd_(nullptr) {}

  bool Init() {
    PRNetAddr addr;
    memset(&addr, 0, sizeof(addr));
    auto status = PR_StringToNetAddr("127.0.0.1", &addr);
    if (status != PR_SUCCESS) {
      std::cerr << "Couldn't get address";
      return false;
    }
    addr.inet.port = PR_htons(4433);

    pr_fd_ = PR_OpenUDPSocket(addr.raw.family);
    if (!pr_fd_) {
      std::cerr << "Couldn't create socket\n";
      return false;
    }
    status = PR_Bind(pr_fd_, &addr);
    if (!pr_fd_) {
      std::cerr << "Couldn't bind socket\n";
      return false;
    }

    return true;
  }

  std::string AddrString(const PRNetAddr& remote) {
      char addr[64];
      char port[7];

      auto rv = PR_NetAddrToString(&remote, addr, sizeof(addr));
      if (rv != PR_SUCCESS) {
        std::cerr << "Couldn't convert address\n";
        return "";
      }

      snprintf(port, sizeof(port), ":%u", PR_ntohs(remote.inet.port));

      return std::string(addr) + port;
  }

  ~Server() {
    if (pr_fd_) {
      PR_Close(pr_fd_);
    }
  }

  void Run() {
    for (;;) {
      uint8_t buf[2048];
      PRNetAddr remote;

      std::cerr << "Main loop\n";

      auto n = PR_RecvFrom(pr_fd_, buf, sizeof(buf), 0,
                           &remote, PR_INTERVAL_NO_TIMEOUT);
      if (n <= 0) {
        continue;
      }

      auto addr = AddrString(remote);

      std::cerr << "Read from " << addr << std::endl;
      auto tmp = peers_.find(addr);
      std::shared_ptr<Agent> peer;

      if (tmp == peers_.end()) {
        peer = std::make_shared<Agent>(pr_fd_, cfg_, remote);

        if (!peer->Init()) {
          std::cerr << "Couldn't init peer\n";
          return;
        }
        peers_[addr] = peer;
      } else {
        peer = tmp->second;
      }

      auto status = peer->NewData(buf, n);
      if (!status) {
        std::cerr << "Handshake failed\n";
      }
    }
  }
 private:
  const Config& cfg_;
  PRFileDesc* pr_fd_;
  std::map<std::string, std::shared_ptr<Agent>> peers_;
};
} // End of namespace.

int main(int argc, char** argv) {
  nss_test::Config config = {
    "key.pem",
    "cert.pem"
  };

  if (NSS_NoDB_Init(nullptr) != SECSuccess) {
    return 1;
  }

  SSL_ConfigServerSessionIDCache(1024, 0, 0, ".");
  nss_test::Server server(config);
  if (!server.Init()) {
    exit(1);
  }

  server.Run();

  exit(0);
}
