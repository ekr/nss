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

    rv = SSL_ResetHandshake(ssl_fd_.get(), PR_TRUE);
    if (rv != SECSuccess) return false;

    return true;
  }

  bool NewData(const uint8_t* buf, size_t len) {
    DataBuffer db(buf, len);

    socket_->PacketReceived(db);

    auto rv = SSL_ForceHandshake(ssl_fd_.get());
    if (rv == SECSuccess) {
      std::cout << "DTLS connected\n";
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

      snprintf(port, size_t(port), ":%u", PR_ntohs(remote.inet.port));

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

      (void)peer->NewData(buf, n);
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
