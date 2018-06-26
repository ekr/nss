/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <queue>

#include "databuffer.h"
#include "dummy_io.h"
#include "scoped_ptrs.h"

namespace nss_test {

class UdpSocket : public DummyIOLayerMethods {
 public:
  UdpSocket(PRFileDesc* pr_fd, const PRNetAddr& peer)
      : pr_fd_(pr_fd), input_(), peer_addr_(peer) {}

  // Create a file descriptor that will reference this object.  The fd
  // must not live longer than this adapter; call PR_Close() before.
  ScopedPRFileDesc CreateFD();

  // Overrides.
  void PacketReceived(const DataBuffer& data);
  int32_t Read(PRFileDesc* f, void* data, int32_t len) override;
  int32_t Recv(PRFileDesc* f, void* buf, int32_t buflen, int32_t flags,
               PRIntervalTime to) override;
  int32_t Write(PRFileDesc* f, const void* buf, int32_t length) override;
 private:
  class Packet : public DataBuffer {
   public:
    Packet(const DataBuffer& buf) : DataBuffer(buf), offset_(0) {}

    void Advance(size_t delta) {
      PR_ASSERT(offset_ + delta <= len());
      offset_ = std::min(len(), offset_ + delta);
    }

    size_t offset() const { return offset_; }
    size_t remaining() const { return len() - offset_; }

   private:
    size_t offset_;
  };

  PRFileDesc* pr_fd_;
  std::queue<Packet> input_;
  PRNetAddr peer_addr_;
};

}
