/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "nss.h"
#include "pk11pub.h"
#include "tls13hkdf.h"
#include <memory>

#include "databuffer.h"
#include "gtest_utils.h"
#include "scoped_ptrs.h"

namespace nss_test {

const uint8_t kKey1Data[] = {
  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
  0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
  0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
  0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
  0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
  0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f
};
const DataBuffer kKey1(kKey1Data,
                       sizeof(kKey1Data));

// The same as key1 but with the first byte
// 0x01.
const uint8_t kKey2Data[] = {
  0x01,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
  0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
  0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
  0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
  0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
  0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f
};
const DataBuffer kKey2(kKey2Data,
                       sizeof(kKey2Data));

const char kLabelMasterSecret[] = "master secret";

const uint8_t kSessionHash[] = {
  0x01,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
  0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
  0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
  0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
  0x01,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
  0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
  0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
  0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
};

static void ImportKey(ScopedPK11SymKey* to, const DataBuffer& key,
                      PK11SlotInfo* slot) {
  SECItem key_item = {
    siBuffer,
    const_cast<uint8_t*>(key.data()),
    static_cast<unsigned int>(key.len())
  };

  PK11SymKey* inner =
      PK11_ImportSymKey(slot, CKM_SSL3_MASTER_KEY_DERIVE, PK11_OriginUnwrap,
                        CKA_DERIVE, &key_item, NULL);
  ASSERT_NE(nullptr, inner);
  to->reset(inner);
}


static void DumpData(const std::string& label, const uint8_t* buf, size_t len) {
  DataBuffer d(buf, len);

  std::cerr << label << ": " << d << std::endl;
}

void DumpKey(const std::string& label, ScopedPK11SymKey& key) {
  SECStatus rv = PK11_ExtractKeyValue(key.get());
  ASSERT_EQ(SECSuccess, rv);

  SECItem *key_data = PK11_GetKeyData(key.get());
  ASSERT_NE(nullptr, key_data);

  DumpData(label, key_data->data, key_data->len);
}

class TlsHkdfTest : public ::testing::Test {
 public:
  TlsHkdfTest() : k1_(), k2_(), slot_(PK11_GetInternalSlot()) {
    EXPECT_NE(nullptr, slot_);
  }

  void SetUp() {
    ImportKey(&k1_, kKey1, slot_.get());
    ImportKey(&k2_, kKey2, slot_.get());
  }

  void VerifyKey(const ScopedPK11SymKey& key, const DataBuffer& expected) {
    SECStatus rv = PK11_ExtractKeyValue(key.get());
    ASSERT_EQ(SECSuccess, rv);

    SECItem *key_data = PK11_GetKeyData(key.get());
    ASSERT_NE(nullptr, key_data);

    EXPECT_EQ(expected.len(), key_data->len);
    EXPECT_EQ(0, memcmp(expected.data(),
                        key_data->data, expected.len()));
  }

  void HkdfExtract(const ScopedPK11SymKey& ikmk1, const ScopedPK11SymKey& ikmk2,
                   SSLHashType base_hash,
                   const DataBuffer& expected) {
    PK11SymKey* prk = nullptr;
    SECStatus rv = tls13_HkdfExtract(
        ikmk1.get(), ikmk2.get(), base_hash, &prk);
    ASSERT_EQ(SECSuccess, rv);
    ScopedPK11SymKey prkk(prk);

    DumpKey("Output", prkk);
    VerifyKey(prkk, expected);
  }

  void HkdfExpandLabel(ScopedPK11SymKey* prk, SSLHashType base_hash,
                       const uint8_t *session_hash, size_t session_hash_len,
                       const char *label, size_t label_len,
                       const DataBuffer& expected) {
    std::vector<uint8_t> output(expected.len());

    SECStatus rv = tls13_HkdfExpandLabelRaw(prk->get(), base_hash,
                                            session_hash, session_hash_len,
                                            label, label_len,
                                            &output[0], output.size());
    ASSERT_EQ(SECSuccess, rv);
    DumpData("Output", &output[0], output.size());
    EXPECT_EQ(0, memcmp(expected.data(), &output[0],
                        expected.len()));
  }

 protected:
  ScopedPK11SymKey k1_;
  ScopedPK11SymKey k2_;

 private:
  ScopedPK11SlotInfo slot_;
};

TEST_F(TlsHkdfTest, HkdfSha256NullNull) {
  const uint8_t expected[] = {
    0x33, 0xad, 0x0a, 0x1c, 0x60, 0x7e, 0xc0, 0x3b,
    0x09, 0xe6, 0xcd, 0x98, 0x93, 0x68, 0x0c, 0xe2,
    0x10, 0xad, 0xf3, 0x00, 0xaa, 0x1f, 0x26, 0x60,
    0xe1, 0xb2, 0x2e, 0x10, 0xf1, 0x70, 0xf9, 0x2a,
  };
  const DataBuffer expected_data(expected, sizeof(expected));

  HkdfExtract(nullptr, nullptr, ssl_hash_sha256,
              expected_data);
}

TEST_F(TlsHkdfTest, HkdfSha256Key1Only) {
  const uint8_t expected[] = {
    0x11, 0x87, 0x38, 0x28, 0xa9, 0x19, 0x78, 0x11,
    0x33, 0x91, 0x24, 0xb5, 0x8a, 0x1b, 0xb0, 0x9f,
    0x7f, 0x0d, 0x8d, 0xbb, 0x10, 0xf4, 0x9c, 0x54,
    0xbd, 0x1f, 0xd8, 0x85, 0xcd, 0x15, 0x30, 0x33,
  };
  const DataBuffer expected_data(expected, sizeof(expected));

  HkdfExtract(k1_, nullptr, ssl_hash_sha256,
              expected_data);
}

TEST_F(TlsHkdfTest, HkdfSha256Key2Only) {
  const uint8_t expected[] = {
    0x2f, 0x5f, 0x78, 0xd0, 0xa4, 0xc4, 0x36, 0xee,
    0x6c, 0x8a, 0x4e, 0xf9, 0xd0, 0x43, 0x81, 0x02,
    0x13, 0xfd, 0x47, 0x83, 0x63, 0x3a, 0xd2, 0xe1,
    0x40, 0x6d, 0x2d, 0x98, 0x00, 0xfd, 0xc1, 0x87
  };
  const DataBuffer expected_data(expected, sizeof(expected));

  HkdfExtract(nullptr, k2_, ssl_hash_sha256,
              expected_data);
}

TEST_F(TlsHkdfTest, HkdfSha256Key1Key2) {
  const uint8_t expected[] = {
    0x79, 0x53, 0xb8, 0xdd, 0x6b, 0x98, 0xce, 0x00,
    0xb7, 0xdc, 0xe8, 0x03, 0x70, 0x8c, 0xe3, 0xac,
    0x06, 0x8b, 0x22, 0xfd, 0x0e, 0x34, 0x48, 0xe6,
    0xe5, 0xe0, 0x8a, 0xd6, 0x16, 0x18, 0xe5, 0x48
  };
  const DataBuffer expected_data(expected, sizeof(expected));

  HkdfExtract(k1_, k2_, ssl_hash_sha256,
              expected_data);
}

TEST_F(TlsHkdfTest, HkdfExpandLabelSha256) {
  const uint8_t expected[] = {
    0x8d, 0x1d, 0x9e, 0x84, 0x59, 0x1d, 0xc9, 0x5d,
    0x41, 0xf8, 0x9d, 0xec, 0xd2, 0xb9, 0x78, 0xb9,
    0xbf, 0xfd, 0x26, 0x9f, 0x94, 0x47, 0x25, 0x78,
    0x1c, 0x5a, 0xd5, 0x06, 0x20, 0x4b, 0xf4, 0xb5
  };
  const DataBuffer expected_data(expected, sizeof(expected));

  HkdfExpandLabel(&k1_, ssl_hash_sha256,
                  kSessionHash, sizeof(kSessionHash),
                  kLabelMasterSecret, strlen(kLabelMasterSecret),
                  expected_data);
}

} // namespace nss_test
