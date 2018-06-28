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

#include "scoped_ptrs.h"

namespace nss_test {

struct Config {
  std::string host;
  uint16_t port;
};

static SECStatus AuthCertificateHook(void* arg, PRFileDesc* fd,
                                     PRBool checksig, PRBool isServer) {
  return SECSuccess;
}

class Client {
 public:
  Client(const Config& cfg) :
      cfg_(cfg),
      pr_fd_(nullptr),
      ssl_fd_(nullptr) {
  }

  bool Init() {
    PRNetAddr addr;
    memset(&addr, 0, sizeof(addr));
    auto status = PR_StringToNetAddr(cfg_.host.c_str(), &addr);
    if (status != PR_SUCCESS) {
      std::cerr << "Couldn't get address";
      return false;
    }
    addr.inet.port = PR_htons(cfg_.port);

    pr_fd_.reset(PR_OpenUDPSocket(addr.raw.family));
    if (!pr_fd_) {
      std::cerr << "Couldn't create socket\n";
      return false;
    }

    status = PR_Connect(pr_fd_.get(), &addr, PR_INTERVAL_NO_TIMEOUT);
    if (status != PR_SUCCESS) {
      std::cerr << "Couldn't connect";
      return false;
    }

    ssl_fd_.reset(DTLS_ImportFD(NULL, pr_fd_.get()));
    if (!ssl_fd_) {
      std::cerr << "Couldn't import socket\n";
      return false;
    }

    auto rv = SSL_OptionSet(ssl_fd_.get(), SSL_NO_CACHE, PR_TRUE);
    if (rv != SECSuccess) return false;

    rv = SSL_AuthCertificateHook(ssl_fd_.get(), AuthCertificateHook, nullptr);
    if (rv != SECSuccess) return false;

    const uint8_t ekt_ciphers[] = {EKT_AESKW_128, EKT_AESKW_256};
    rv = SSL_SetEKTCiphers(ssl_fd_.get(), ekt_ciphers, PR_ARRAY_SIZE(ekt_ciphers));
    if (rv != SECSuccess) return false;

    const uint16_t srtp_ciphers[] = {SRTP_AES128_CM_HMAC_SHA1_80,
                                     SRTP_AES128_CM_HMAC_SHA1_32};
    rv = SSL_SetSRTPCiphers(ssl_fd_.get(), srtp_ciphers, PR_ARRAY_SIZE(srtp_ciphers));
    if (rv != SECSuccess) return false;

    rv = SSL_ResetHandshake(ssl_fd_.get(), PR_FALSE);
    if (rv != SECSuccess) return false;

    return true;
  }

  bool Run() {
    for (;;) {
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

        std::cout << "EKT cipher: " << static_cast<int>(cipher) << std::endl;

        uint16_t srtp;
        rv = SSL_GetSRTPCipher(ssl_fd_.get(), &srtp);
        if (rv != SECSuccess) {
          return false;
        }

        std::cout << "SRTP cipher: " << srtp << std::endl;

        return true;
      } else {
        auto err = PR_GetError();
        if (err == PR_WOULD_BLOCK_ERROR) {
          std::cout << "Would have blocked\n";
        } else {
          std::cout << "Error: " << PORT_ErrorToName(err) << std::endl;
          return false;
        }
      }
    }
  }

 private:
  const Config& cfg_;
  ScopedPRFileDesc pr_fd_;
  ScopedPRFileDesc ssl_fd_;
};


} // End of namespace.

int main(int argc, char** argv) {
  nss_test::Config config = {
    "127.0.0.1",
    4433
  };

  if (NSS_NoDB_Init(nullptr) != SECSuccess) {
    return 1;
  }

  nss_test::Client client(config);
  if (!client.Init()) {
    exit(1);
  }

  auto rv = client.Run();
  std::cerr << "Result: " << (rv ? "Success" : "Failure") << "\n";

  exit(0);
}
