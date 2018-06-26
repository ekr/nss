/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "dummy_io.h"
#include "scoped_ptrs.h"

#include "udp_socket.h"

namespace nss_test {

ScopedPRFileDesc UdpSocket::CreateFD() {
  static PRDescIdentity test_fd_identity =
      PR_GetUniqueIdentity("udp_socket");
  return DummyIOLayerMethods::CreateFD(test_fd_identity, this);
}

void UdpSocket::PacketReceived(const DataBuffer &packet) {
  input_.push(Packet(packet));
}

int32_t UdpSocket::Read(PRFileDesc *f, void *data, int32_t len) {
  PR_SetError(PR_INVALID_METHOD_ERROR, 0);
  return -1;
}

int32_t UdpSocket::Recv(PRFileDesc *f, void *buf, int32_t buflen,
                        int32_t flags, PRIntervalTime to) {
  PR_ASSERT(flags == 0);
  if (flags != 0) {
    PR_SetError(PR_NOT_IMPLEMENTED_ERROR, 0);
    return -1;
  }

  if (input_.empty()) {
    PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
    return -1;
  }

  auto &front = input_.front();
  if (static_cast<size_t>(buflen) < front.len()) {
    PR_ASSERT(false);
    PR_SetError(PR_BUFFER_OVERFLOW_ERROR, 0);
    return -1;
  }

  size_t count = front.len();
  memcpy(buf, front.data(), count);

  input_.pop();
  return static_cast<int32_t>(count);
}

int32_t UdpSocket::Write(PRFileDesc *f, const void *buf, int32_t length) {
  return PR_SendTo(pr_fd_, buf, length, 0, &peer_addr_, PR_INTERVAL_NO_TIMEOUT);
}

}
