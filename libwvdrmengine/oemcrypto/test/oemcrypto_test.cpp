// Copyright 2013 Google Inc. All Rights Reserved.

//
// OEMCrypto unit tests
//
#include <arpa/inet.h>  // TODO(fredgc): Add ntoh to wv_cdm_utilities.h
#include <ctype.h>
#include <getopt.h>
#include <gtest/gtest.h>
#include <openssl/aes.h>
#include <openssl/cmac.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <sys/types.h>
#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include "OEMCryptoCENC.h"
#include "oemcrypto_key_mock.h"
#include "string_conversions.h"
#include "wv_cdm_constants.h"
#include "wv_keybox.h"

using namespace std;

namespace {
const size_t kNumKeys = 4;
const size_t kBufferMaxLength = 256;
#if defined(TEST_SPEED_MULTIPLIER)  // Can slow test time limits when
                                    // debugging is slowing everything.
const int kSpeedMultiplier = TEST_SPEED_MULTIPLIER1;
#else
const int kSpeedMultiplier = 1;
#endif
const int kShortSleep = 1 * kSpeedMultiplier;
const int kLongSleep = 2 * kSpeedMultiplier;
const uint32_t kDuration = 2 * kSpeedMultiplier;
const uint32_t kLongDuration = 5 * kSpeedMultiplier;
}

namespace wvoec {

typedef struct {
  uint8_t verification[4];
  uint32_t duration;
  uint32_t nonce;
  uint32_t control_bits;
}  KeyControlBlock;

const size_t kTestKeyIdLength = 12;  // pick a length. any length.
typedef struct {
  uint8_t key_id[kTestKeyIdLength];
  uint8_t key_data[wvcdm::MAC_KEY_SIZE];
  size_t key_data_length;
  uint8_t key_iv[wvcdm::KEY_IV_SIZE];
  uint8_t control_iv[wvcdm::KEY_IV_SIZE];
  KeyControlBlock control;
} MessageKeyData;

struct MessageData {
  MessageKeyData keys[kNumKeys];
  uint8_t mac_key_iv[wvcdm::KEY_IV_SIZE];
  uint8_t mac_keys[2*wvcdm::MAC_KEY_SIZE];
};

const size_t kMaxTestRSAKeyLength = 2000;  // Rough estimate.
struct RSAPrivateKeyMessage {
  uint8_t rsa_key[kMaxTestRSAKeyLength];
  uint8_t rsa_key_iv[wvcdm::KEY_IV_SIZE];
  size_t rsa_key_length;
  uint32_t nonce;
};

const wvoec_mock::WidevineKeybox kDefaultKeybox = {
  // Sample keybox used for test vectors
  {
    // deviceID
    0x54, 0x65, 0x73, 0x74, 0x4b, 0x65, 0x79, 0x30,  // TestKey01
    0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // ........
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // ........
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // ........
  }, {
    // key
    0xfb, 0xda, 0x04, 0x89, 0xa1, 0x58, 0x16, 0x0e,
    0xa4, 0x02, 0xe9, 0x29, 0xe3, 0xb6, 0x8f, 0x04,
  }, {
    // data
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x10, 0x19,
    0x07, 0xd9, 0xff, 0xde, 0x13, 0xaa, 0x95, 0xc1,
    0x22, 0x67, 0x80, 0x53, 0x36, 0x21, 0x36, 0xbd,
    0xf8, 0x40, 0x8f, 0x82, 0x76, 0xe4, 0xc2, 0xd8,
    0x7e, 0xc5, 0x2b, 0x61, 0xaa, 0x1b, 0x9f, 0x64,
    0x6e, 0x58, 0x73, 0x49, 0x30, 0xac, 0xeb, 0xe8,
    0x99, 0xb3, 0xe4, 0x64, 0x18, 0x9a, 0x14, 0xa8,
    0x72, 0x02, 0xfb, 0x02, 0x57, 0x4e, 0x70, 0x64,
    0x0b, 0xd2, 0x2e, 0xf4, 0x4b, 0x2d, 0x7e, 0x39,
  }, {
    // magic
    0x6b, 0x62, 0x6f, 0x78,
  }, {
    // Crc
    0x0a, 0x7a, 0x2c, 0x35,
  }
};

static wvoec_mock::WidevineKeybox kValidKeybox02 = {
  // Sample keybox used for test vectors
  {
    // deviceID
    0x54, 0x65, 0x73, 0x74, 0x4b, 0x65, 0x79, 0x30, // TestKey02
    0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
  }, {
    // key
    0x76, 0x5d, 0xce, 0x01, 0x04, 0x89, 0xb3, 0xd0,
    0xdf, 0xce, 0x54, 0x8a, 0x49, 0xda, 0xdc, 0xb6,
  }, {
    // data
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x10, 0x19,
    0x92, 0x27, 0x0b, 0x1f, 0x1a, 0xd5, 0xc6, 0x93,
    0x19, 0x3f, 0xaa, 0x74, 0x1f, 0xdd, 0x5f, 0xb4,
    0xe9, 0x40, 0x2f, 0x34, 0xa4, 0x92, 0xf4, 0xae,
    0x9a, 0x52, 0x39, 0xbc, 0xb7, 0x24, 0x38, 0x13,
    0xab, 0xf4, 0x92, 0x96, 0xc4, 0x81, 0x60, 0x33,
    0xd8, 0xb8, 0x09, 0xc7, 0x55, 0x0e, 0x12, 0xfa,
    0xa8, 0x98, 0x62, 0x8a, 0xec, 0xea, 0x74, 0x8a,
    0x4b, 0xfa, 0x5a, 0x9e, 0xb6, 0x49, 0x0d, 0x80,
  }, {
    // magic
    0x6b, 0x62, 0x6f, 0x78,
  }, {
    // Crc
    0x2a, 0x3b, 0x3e, 0xe4,
  }
};

static wvoec_mock::WidevineKeybox kValidKeybox03 = {
  // Sample keybox used for test vectors
  {
    // deviceID
    0x54, 0x65, 0x73, 0x74, 0x4b, 0x65, 0x79, 0x30, // TestKey03
    0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
  }, {
    // key
    0x25, 0xe5, 0x2a, 0x02, 0x29, 0x68, 0x04, 0xa2,
    0x92, 0xfd, 0x7c, 0x67, 0x0b, 0x67, 0x1f, 0x31,
  }, {
    // data
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x10, 0x19,
    0xf4, 0x0a, 0x0e, 0xa2, 0x0a, 0x71, 0xd5, 0x92,
    0xfa, 0xa3, 0x25, 0xc6, 0x4b, 0x76, 0xf1, 0x64,
    0xf4, 0x60, 0xa0, 0x30, 0x72, 0x23, 0xbe, 0x03,
    0xcd, 0xde, 0x7a, 0x06, 0xd4, 0x01, 0xeb, 0xdc,
    0xe0, 0x50, 0xc0, 0x53, 0x0a, 0x50, 0xb0, 0x37,
    0xe5, 0x05, 0x25, 0x0e, 0xa4, 0xc8, 0x5a, 0xff,
    0x46, 0x6e, 0xa5, 0x31, 0xf3, 0xdd, 0x94, 0xb7,
    0xe0, 0xd3, 0xf9, 0x04, 0xb2, 0x54, 0xb1, 0x64,
  }, {
    // magic
    0x6b, 0x62, 0x6f, 0x78,
  }, {
    // Crc
    0xa1, 0x99, 0x5f, 0x46,
  }
};

/* Note: Key 1 was 3072 bits. We are only generating 2048 bit keys,
   so we do not need to test with 3072 bit keys. */

static const uint8_t kTestPKCS1RSAPrivateKey2_2048[] = {
  0x30, 0x82, 0x04, 0xa2, 0x02, 0x01, 0x00, 0x02,
  0x82, 0x01, 0x01, 0x00, 0xa7, 0x00, 0x36, 0x60,
  0x65, 0xdc, 0xbd, 0x54, 0x5a, 0x2a, 0x40, 0xb4,
  0xe1, 0x15, 0x94, 0x58, 0x11, 0x4f, 0x94, 0x58,
  0xdd, 0xde, 0xa7, 0x1f, 0x3c, 0x2c, 0xe0, 0x88,
  0x09, 0x29, 0x61, 0x57, 0x67, 0x5e, 0x56, 0x7e,
  0xee, 0x27, 0x8f, 0x59, 0x34, 0x9a, 0x2a, 0xaa,
  0x9d, 0xb4, 0x4e, 0xfa, 0xa7, 0x6a, 0xd4, 0xc9,
  0x7a, 0x53, 0xc1, 0x4e, 0x9f, 0xe3, 0x34, 0xf7,
  0x3d, 0xb7, 0xc9, 0x10, 0x47, 0x4f, 0x28, 0xda,
  0x3f, 0xce, 0x31, 0x7b, 0xfd, 0x06, 0x10, 0xeb,
  0xf7, 0xbe, 0x92, 0xf9, 0xaf, 0xfb, 0x3e, 0x68,
  0xda, 0xee, 0x1a, 0x64, 0x4c, 0xf3, 0x29, 0xf2,
  0x73, 0x9e, 0x39, 0xd8, 0xf6, 0x6f, 0xd8, 0xb2,
  0x80, 0x82, 0x71, 0x8e, 0xb5, 0xa4, 0xf2, 0xc2,
  0x3e, 0xcd, 0x0a, 0xca, 0xb6, 0x04, 0xcd, 0x9a,
  0x13, 0x8b, 0x54, 0x73, 0x54, 0x25, 0x54, 0x8c,
  0xbe, 0x98, 0x7a, 0x67, 0xad, 0xda, 0xb3, 0x4e,
  0xb3, 0xfa, 0x82, 0xa8, 0x4a, 0x67, 0x98, 0x56,
  0x57, 0x54, 0x71, 0xcd, 0x12, 0x7f, 0xed, 0xa3,
  0x01, 0xc0, 0x6a, 0x8b, 0x24, 0x03, 0x96, 0x88,
  0xbe, 0x97, 0x66, 0x2a, 0xbc, 0x53, 0xc9, 0x83,
  0x06, 0x51, 0x5a, 0x88, 0x65, 0x13, 0x18, 0xe4,
  0x3a, 0xed, 0x6b, 0xf1, 0x61, 0x5b, 0x4c, 0xc8,
  0x1e, 0xf4, 0xc2, 0xae, 0x08, 0x5e, 0x2d, 0x5f,
  0xf8, 0x12, 0x7f, 0xa2, 0xfc, 0xbb, 0x21, 0x18,
  0x30, 0xda, 0xfe, 0x40, 0xfb, 0x01, 0xca, 0x2e,
  0x37, 0x0e, 0xce, 0xdd, 0x76, 0x87, 0x82, 0x46,
  0x0b, 0x3a, 0x77, 0x8f, 0xc0, 0x72, 0x07, 0x2c,
  0x7f, 0x9d, 0x1e, 0x86, 0x5b, 0xed, 0x27, 0x29,
  0xdf, 0x03, 0x97, 0x62, 0xef, 0x44, 0xd3, 0x5b,
  0x3d, 0xdb, 0x9c, 0x5e, 0x1b, 0x7b, 0x39, 0xb4,
  0x0b, 0x6d, 0x04, 0x6b, 0xbb, 0xbb, 0x2c, 0x5f,
  0xcf, 0xb3, 0x7a, 0x05, 0x02, 0x03, 0x01, 0x00,
  0x01, 0x02, 0x82, 0x01, 0x00, 0x5e, 0x79, 0x65,
  0x49, 0xa5, 0x76, 0x79, 0xf9, 0x05, 0x45, 0x0f,
  0xf4, 0x03, 0xbd, 0xa4, 0x7d, 0x29, 0xd5, 0xde,
  0x33, 0x63, 0xd8, 0xb8, 0xac, 0x97, 0xeb, 0x3f,
  0x5e, 0x55, 0xe8, 0x7d, 0xf3, 0xe7, 0x3b, 0x5c,
  0x2d, 0x54, 0x67, 0x36, 0xd6, 0x1d, 0x46, 0xf5,
  0xca, 0x2d, 0x8b, 0x3a, 0x7e, 0xdc, 0x45, 0x38,
  0x79, 0x7e, 0x65, 0x71, 0x5f, 0x1c, 0x5e, 0x79,
  0xb1, 0x40, 0xcd, 0xfe, 0xc5, 0xe1, 0xc1, 0x6b,
  0x78, 0x04, 0x4e, 0x8e, 0x79, 0xf9, 0x0a, 0xfc,
  0x79, 0xb1, 0x5e, 0xb3, 0x60, 0xe3, 0x68, 0x7b,
  0xc6, 0xef, 0xcb, 0x71, 0x4c, 0xba, 0xa7, 0x79,
  0x5c, 0x7a, 0x81, 0xd1, 0x71, 0xe7, 0x00, 0x21,
  0x13, 0xe2, 0x55, 0x69, 0x0e, 0x75, 0xbe, 0x09,
  0xc3, 0x4f, 0xa9, 0xc9, 0x68, 0x22, 0x0e, 0x97,
  0x8d, 0x89, 0x6e, 0xf1, 0xe8, 0x88, 0x7a, 0xd1,
  0xd9, 0x09, 0x5d, 0xd3, 0x28, 0x78, 0x25, 0x0b,
  0x1c, 0x47, 0x73, 0x25, 0xcc, 0x21, 0xb6, 0xda,
  0xc6, 0x24, 0x5a, 0xd0, 0x37, 0x14, 0x46, 0xc7,
  0x94, 0x69, 0xe4, 0x43, 0x6f, 0x47, 0xde, 0x00,
  0x33, 0x4d, 0x8f, 0x95, 0x72, 0xfa, 0x68, 0x71,
  0x17, 0x66, 0x12, 0x1a, 0x87, 0x27, 0xf7, 0xef,
  0x7e, 0xe0, 0x35, 0x58, 0xf2, 0x4d, 0x6f, 0x35,
  0x01, 0xaa, 0x96, 0xe2, 0x3d, 0x51, 0x13, 0x86,
  0x9c, 0x79, 0xd0, 0xb7, 0xb6, 0x64, 0xe8, 0x86,
  0x65, 0x50, 0xbf, 0xcc, 0x27, 0x53, 0x1f, 0x51,
  0xd4, 0xca, 0xbe, 0xf5, 0xdd, 0x77, 0x70, 0x98,
  0x0f, 0xee, 0xa8, 0x96, 0x07, 0x5f, 0x45, 0x6a,
  0x7a, 0x0d, 0x03, 0x9c, 0x4f, 0x29, 0xf6, 0x06,
  0xf3, 0x5d, 0x58, 0x6c, 0x47, 0xd0, 0x96, 0xa9,
  0x03, 0x17, 0xbb, 0x4e, 0xc9, 0x21, 0xe0, 0xac,
  0xcd, 0x78, 0x78, 0xb2, 0xfe, 0x81, 0xb2, 0x51,
  0x53, 0xa6, 0x1f, 0x98, 0x45, 0x02, 0x81, 0x81,
  0x00, 0xcf, 0x73, 0x8c, 0xbe, 0x6d, 0x45, 0x2d,
  0x0c, 0x0b, 0x5d, 0x5c, 0x6c, 0x75, 0x78, 0xcc,
  0x35, 0x48, 0xb6, 0x98, 0xf1, 0xb9, 0x64, 0x60,
  0x8c, 0x43, 0xeb, 0x85, 0xab, 0x04, 0xb6, 0x7d,
  0x1b, 0x71, 0x75, 0x06, 0xe2, 0xda, 0x84, 0x68,
  0x2e, 0x7f, 0x4c, 0xe3, 0x73, 0xb4, 0xde, 0x51,
  0x4b, 0xb6, 0x51, 0x86, 0x7b, 0xd0, 0xe6, 0x4d,
  0xf3, 0xd1, 0xcf, 0x1a, 0xfe, 0x7f, 0x3a, 0x83,
  0xba, 0xb3, 0xe1, 0xff, 0x54, 0x13, 0x93, 0xd7,
  0x9c, 0x27, 0x80, 0xb7, 0x1e, 0x64, 0x9e, 0xf7,
  0x32, 0x2b, 0x46, 0x29, 0xf7, 0xf8, 0x18, 0x6c,
  0xf7, 0x4a, 0xbe, 0x4b, 0xee, 0x96, 0x90, 0x8f,
  0xa2, 0x16, 0x22, 0x6a, 0xcc, 0x48, 0x06, 0x74,
  0x63, 0x43, 0x7f, 0x27, 0x22, 0x44, 0x3c, 0x2d,
  0x3b, 0x62, 0xf1, 0x1c, 0xb4, 0x27, 0x33, 0x85,
  0x26, 0x60, 0x48, 0x16, 0xcb, 0xef, 0xf8, 0xcd,
  0x37, 0x02, 0x81, 0x81, 0x00, 0xce, 0x15, 0x43,
  0x6e, 0x4b, 0x0f, 0xf9, 0x3f, 0x87, 0xc3, 0x41,
  0x45, 0x97, 0xb1, 0x49, 0xc2, 0x19, 0x23, 0x87,
  0xe4, 0x24, 0x1c, 0x64, 0xe5, 0x28, 0xcb, 0x43,
  0x10, 0x14, 0x14, 0x0e, 0x19, 0xcb, 0xbb, 0xdb,
  0xfd, 0x11, 0x9d, 0x17, 0x68, 0x78, 0x6d, 0x61,
  0x70, 0x63, 0x3a, 0xa1, 0xb3, 0xf3, 0xa7, 0x5b,
  0x0e, 0xff, 0xb7, 0x61, 0x11, 0x54, 0x91, 0x99,
  0xe5, 0x91, 0x32, 0x2d, 0xeb, 0x3f, 0xd8, 0x3e,
  0xf7, 0xd4, 0xcb, 0xd2, 0xa3, 0x41, 0xc1, 0xee,
  0xc6, 0x92, 0x13, 0xeb, 0x7f, 0x42, 0x58, 0xf4,
  0xd0, 0xb2, 0x74, 0x1d, 0x8e, 0x87, 0x46, 0xcd,
  0x14, 0xb8, 0x16, 0xad, 0xb5, 0xbd, 0x0d, 0x6c,
  0x95, 0x5a, 0x16, 0xbf, 0xe9, 0x53, 0xda, 0xfb,
  0xed, 0x83, 0x51, 0x67, 0xa9, 0x55, 0xab, 0x54,
  0x02, 0x95, 0x20, 0xa6, 0x68, 0x17, 0x53, 0xa8,
  0xea, 0x43, 0xe5, 0xb0, 0xa3, 0x02, 0x81, 0x80,
  0x67, 0x9c, 0x32, 0x83, 0x39, 0x57, 0xff, 0x73,
  0xb0, 0x89, 0x64, 0x8b, 0xd6, 0xf0, 0x0a, 0x2d,
  0xe2, 0xaf, 0x30, 0x1c, 0x2a, 0x97, 0xf3, 0x90,
  0x9a, 0xab, 0x9b, 0x0b, 0x1b, 0x43, 0x79, 0xa0,
  0xa7, 0x3d, 0xe7, 0xbe, 0x8d, 0x9c, 0xeb, 0xdb,
  0xad, 0x40, 0xdd, 0xa9, 0x00, 0x80, 0xb8, 0xe1,
  0xb3, 0xa1, 0x6c, 0x25, 0x92, 0xe4, 0x33, 0xb2,
  0xbe, 0xeb, 0x4d, 0x74, 0x26, 0x5f, 0x37, 0x43,
  0x9c, 0x6c, 0x17, 0x76, 0x0a, 0x81, 0x20, 0x82,
  0xa1, 0x48, 0x2c, 0x2d, 0x45, 0xdc, 0x0f, 0x62,
  0x43, 0x32, 0xbb, 0xeb, 0x59, 0x41, 0xf9, 0xca,
  0x58, 0xce, 0x4a, 0x66, 0x53, 0x54, 0xc8, 0x28,
  0x10, 0x1e, 0x08, 0x71, 0x16, 0xd8, 0x02, 0x71,
  0x41, 0x58, 0xd4, 0x56, 0xcc, 0xf5, 0xb1, 0x31,
  0xa3, 0xed, 0x00, 0x85, 0x09, 0xbf, 0x35, 0x95,
  0x41, 0x29, 0x40, 0x19, 0x83, 0x35, 0x24, 0x69,
  0x02, 0x81, 0x80, 0x55, 0x10, 0x0b, 0xcc, 0x3b,
  0xa9, 0x75, 0x3d, 0x16, 0xe1, 0xae, 0x50, 0x76,
  0x63, 0x94, 0x49, 0x4c, 0xad, 0x10, 0xcb, 0x47,
  0x68, 0x7c, 0xf0, 0xe5, 0xdc, 0xb8, 0x6a, 0xab,
  0x8e, 0xf7, 0x9f, 0x08, 0x2c, 0x1b, 0x8a, 0xa2,
  0xb9, 0x8f, 0xce, 0xec, 0x5e, 0x61, 0xa8, 0xcd,
  0x1c, 0x87, 0x60, 0x4a, 0xc3, 0x1a, 0x5f, 0xdf,
  0x87, 0x26, 0xc6, 0xcb, 0x7c, 0x69, 0xe4, 0x8b,
  0x01, 0x06, 0x59, 0x22, 0xfa, 0x34, 0x4b, 0x81,
  0x87, 0x3c, 0x03, 0x6d, 0x02, 0x0a, 0x77, 0xe6,
  0x15, 0xd8, 0xcf, 0xa7, 0x68, 0x26, 0x6c, 0xfa,
  0x2b, 0xd9, 0x83, 0x5a, 0x2d, 0x0c, 0x3b, 0x70,
  0x1c, 0xd4, 0x48, 0xbe, 0xa7, 0x0a, 0xd9, 0xbe,
  0xdc, 0xc3, 0x0c, 0x21, 0x33, 0xb3, 0x66, 0xff,
  0x1c, 0x1b, 0xc8, 0x96, 0x76, 0xe8, 0x6f, 0x44,
  0x74, 0xbc, 0x9b, 0x1c, 0x7d, 0xc8, 0xac, 0x21,
  0xa8, 0x6e, 0x37, 0x02, 0x81, 0x80, 0x2c, 0x7c,
  0xad, 0x1e, 0x75, 0xf6, 0x69, 0x1d, 0xe7, 0xa6,
  0xca, 0x74, 0x7d, 0x67, 0xc8, 0x65, 0x28, 0x66,
  0xc4, 0x43, 0xa6, 0xbd, 0x40, 0x57, 0xae, 0xb7,
  0x65, 0x2c, 0x52, 0xf9, 0xe4, 0xc7, 0x81, 0x7b,
  0x56, 0xa3, 0xd2, 0x0d, 0xe8, 0x33, 0x70, 0xcf,
  0x06, 0x84, 0xb3, 0x4e, 0x44, 0x50, 0x75, 0x61,
  0x96, 0x86, 0x4b, 0xb6, 0x2b, 0xad, 0xf0, 0xad,
  0x57, 0xd0, 0x37, 0x0d, 0x1d, 0x35, 0x50, 0xcb,
  0x69, 0x22, 0x39, 0x29, 0xb9, 0x3a, 0xd3, 0x29,
  0x23, 0x02, 0x60, 0xf7, 0xab, 0x30, 0x40, 0xda,
  0x8e, 0x4d, 0x45, 0x70, 0x26, 0xf4, 0xa2, 0x0d,
  0xd0, 0x64, 0x5d, 0x47, 0x3c, 0x18, 0xf4, 0xd4,
  0x52, 0x95, 0x00, 0xae, 0x84, 0x6b, 0x47, 0xb2,
  0x3c, 0x82, 0xd3, 0x72, 0x53, 0xde, 0x72, 0x2c,
  0xf7, 0xc1, 0x22, 0x36, 0xd9, 0x18, 0x56, 0xfe,
  0x39, 0x28, 0x33, 0xe0, 0xdb, 0x03 };

// 2048 bit RSA key in PKCS#8 PrivateKeyInfo
static const uint8_t kTestRSAPKCS8PrivateKeyInfo2_2048[] = {
  0x30, 0x82, 0x04, 0xbc, 0x02, 0x01, 0x00, 0x30,
  0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
  0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82,
  0x04, 0xa6, 0x30, 0x82, 0x04, 0xa2, 0x02, 0x01,
  0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0xa7, 0x00,
  0x36, 0x60, 0x65, 0xdc, 0xbd, 0x54, 0x5a, 0x2a,
  0x40, 0xb4, 0xe1, 0x15, 0x94, 0x58, 0x11, 0x4f,
  0x94, 0x58, 0xdd, 0xde, 0xa7, 0x1f, 0x3c, 0x2c,
  0xe0, 0x88, 0x09, 0x29, 0x61, 0x57, 0x67, 0x5e,
  0x56, 0x7e, 0xee, 0x27, 0x8f, 0x59, 0x34, 0x9a,
  0x2a, 0xaa, 0x9d, 0xb4, 0x4e, 0xfa, 0xa7, 0x6a,
  0xd4, 0xc9, 0x7a, 0x53, 0xc1, 0x4e, 0x9f, 0xe3,
  0x34, 0xf7, 0x3d, 0xb7, 0xc9, 0x10, 0x47, 0x4f,
  0x28, 0xda, 0x3f, 0xce, 0x31, 0x7b, 0xfd, 0x06,
  0x10, 0xeb, 0xf7, 0xbe, 0x92, 0xf9, 0xaf, 0xfb,
  0x3e, 0x68, 0xda, 0xee, 0x1a, 0x64, 0x4c, 0xf3,
  0x29, 0xf2, 0x73, 0x9e, 0x39, 0xd8, 0xf6, 0x6f,
  0xd8, 0xb2, 0x80, 0x82, 0x71, 0x8e, 0xb5, 0xa4,
  0xf2, 0xc2, 0x3e, 0xcd, 0x0a, 0xca, 0xb6, 0x04,
  0xcd, 0x9a, 0x13, 0x8b, 0x54, 0x73, 0x54, 0x25,
  0x54, 0x8c, 0xbe, 0x98, 0x7a, 0x67, 0xad, 0xda,
  0xb3, 0x4e, 0xb3, 0xfa, 0x82, 0xa8, 0x4a, 0x67,
  0x98, 0x56, 0x57, 0x54, 0x71, 0xcd, 0x12, 0x7f,
  0xed, 0xa3, 0x01, 0xc0, 0x6a, 0x8b, 0x24, 0x03,
  0x96, 0x88, 0xbe, 0x97, 0x66, 0x2a, 0xbc, 0x53,
  0xc9, 0x83, 0x06, 0x51, 0x5a, 0x88, 0x65, 0x13,
  0x18, 0xe4, 0x3a, 0xed, 0x6b, 0xf1, 0x61, 0x5b,
  0x4c, 0xc8, 0x1e, 0xf4, 0xc2, 0xae, 0x08, 0x5e,
  0x2d, 0x5f, 0xf8, 0x12, 0x7f, 0xa2, 0xfc, 0xbb,
  0x21, 0x18, 0x30, 0xda, 0xfe, 0x40, 0xfb, 0x01,
  0xca, 0x2e, 0x37, 0x0e, 0xce, 0xdd, 0x76, 0x87,
  0x82, 0x46, 0x0b, 0x3a, 0x77, 0x8f, 0xc0, 0x72,
  0x07, 0x2c, 0x7f, 0x9d, 0x1e, 0x86, 0x5b, 0xed,
  0x27, 0x29, 0xdf, 0x03, 0x97, 0x62, 0xef, 0x44,
  0xd3, 0x5b, 0x3d, 0xdb, 0x9c, 0x5e, 0x1b, 0x7b,
  0x39, 0xb4, 0x0b, 0x6d, 0x04, 0x6b, 0xbb, 0xbb,
  0x2c, 0x5f, 0xcf, 0xb3, 0x7a, 0x05, 0x02, 0x03,
  0x01, 0x00, 0x01, 0x02, 0x82, 0x01, 0x00, 0x5e,
  0x79, 0x65, 0x49, 0xa5, 0x76, 0x79, 0xf9, 0x05,
  0x45, 0x0f, 0xf4, 0x03, 0xbd, 0xa4, 0x7d, 0x29,
  0xd5, 0xde, 0x33, 0x63, 0xd8, 0xb8, 0xac, 0x97,
  0xeb, 0x3f, 0x5e, 0x55, 0xe8, 0x7d, 0xf3, 0xe7,
  0x3b, 0x5c, 0x2d, 0x54, 0x67, 0x36, 0xd6, 0x1d,
  0x46, 0xf5, 0xca, 0x2d, 0x8b, 0x3a, 0x7e, 0xdc,
  0x45, 0x38, 0x79, 0x7e, 0x65, 0x71, 0x5f, 0x1c,
  0x5e, 0x79, 0xb1, 0x40, 0xcd, 0xfe, 0xc5, 0xe1,
  0xc1, 0x6b, 0x78, 0x04, 0x4e, 0x8e, 0x79, 0xf9,
  0x0a, 0xfc, 0x79, 0xb1, 0x5e, 0xb3, 0x60, 0xe3,
  0x68, 0x7b, 0xc6, 0xef, 0xcb, 0x71, 0x4c, 0xba,
  0xa7, 0x79, 0x5c, 0x7a, 0x81, 0xd1, 0x71, 0xe7,
  0x00, 0x21, 0x13, 0xe2, 0x55, 0x69, 0x0e, 0x75,
  0xbe, 0x09, 0xc3, 0x4f, 0xa9, 0xc9, 0x68, 0x22,
  0x0e, 0x97, 0x8d, 0x89, 0x6e, 0xf1, 0xe8, 0x88,
  0x7a, 0xd1, 0xd9, 0x09, 0x5d, 0xd3, 0x28, 0x78,
  0x25, 0x0b, 0x1c, 0x47, 0x73, 0x25, 0xcc, 0x21,
  0xb6, 0xda, 0xc6, 0x24, 0x5a, 0xd0, 0x37, 0x14,
  0x46, 0xc7, 0x94, 0x69, 0xe4, 0x43, 0x6f, 0x47,
  0xde, 0x00, 0x33, 0x4d, 0x8f, 0x95, 0x72, 0xfa,
  0x68, 0x71, 0x17, 0x66, 0x12, 0x1a, 0x87, 0x27,
  0xf7, 0xef, 0x7e, 0xe0, 0x35, 0x58, 0xf2, 0x4d,
  0x6f, 0x35, 0x01, 0xaa, 0x96, 0xe2, 0x3d, 0x51,
  0x13, 0x86, 0x9c, 0x79, 0xd0, 0xb7, 0xb6, 0x64,
  0xe8, 0x86, 0x65, 0x50, 0xbf, 0xcc, 0x27, 0x53,
  0x1f, 0x51, 0xd4, 0xca, 0xbe, 0xf5, 0xdd, 0x77,
  0x70, 0x98, 0x0f, 0xee, 0xa8, 0x96, 0x07, 0x5f,
  0x45, 0x6a, 0x7a, 0x0d, 0x03, 0x9c, 0x4f, 0x29,
  0xf6, 0x06, 0xf3, 0x5d, 0x58, 0x6c, 0x47, 0xd0,
  0x96, 0xa9, 0x03, 0x17, 0xbb, 0x4e, 0xc9, 0x21,
  0xe0, 0xac, 0xcd, 0x78, 0x78, 0xb2, 0xfe, 0x81,
  0xb2, 0x51, 0x53, 0xa6, 0x1f, 0x98, 0x45, 0x02,
  0x81, 0x81, 0x00, 0xcf, 0x73, 0x8c, 0xbe, 0x6d,
  0x45, 0x2d, 0x0c, 0x0b, 0x5d, 0x5c, 0x6c, 0x75,
  0x78, 0xcc, 0x35, 0x48, 0xb6, 0x98, 0xf1, 0xb9,
  0x64, 0x60, 0x8c, 0x43, 0xeb, 0x85, 0xab, 0x04,
  0xb6, 0x7d, 0x1b, 0x71, 0x75, 0x06, 0xe2, 0xda,
  0x84, 0x68, 0x2e, 0x7f, 0x4c, 0xe3, 0x73, 0xb4,
  0xde, 0x51, 0x4b, 0xb6, 0x51, 0x86, 0x7b, 0xd0,
  0xe6, 0x4d, 0xf3, 0xd1, 0xcf, 0x1a, 0xfe, 0x7f,
  0x3a, 0x83, 0xba, 0xb3, 0xe1, 0xff, 0x54, 0x13,
  0x93, 0xd7, 0x9c, 0x27, 0x80, 0xb7, 0x1e, 0x64,
  0x9e, 0xf7, 0x32, 0x2b, 0x46, 0x29, 0xf7, 0xf8,
  0x18, 0x6c, 0xf7, 0x4a, 0xbe, 0x4b, 0xee, 0x96,
  0x90, 0x8f, 0xa2, 0x16, 0x22, 0x6a, 0xcc, 0x48,
  0x06, 0x74, 0x63, 0x43, 0x7f, 0x27, 0x22, 0x44,
  0x3c, 0x2d, 0x3b, 0x62, 0xf1, 0x1c, 0xb4, 0x27,
  0x33, 0x85, 0x26, 0x60, 0x48, 0x16, 0xcb, 0xef,
  0xf8, 0xcd, 0x37, 0x02, 0x81, 0x81, 0x00, 0xce,
  0x15, 0x43, 0x6e, 0x4b, 0x0f, 0xf9, 0x3f, 0x87,
  0xc3, 0x41, 0x45, 0x97, 0xb1, 0x49, 0xc2, 0x19,
  0x23, 0x87, 0xe4, 0x24, 0x1c, 0x64, 0xe5, 0x28,
  0xcb, 0x43, 0x10, 0x14, 0x14, 0x0e, 0x19, 0xcb,
  0xbb, 0xdb, 0xfd, 0x11, 0x9d, 0x17, 0x68, 0x78,
  0x6d, 0x61, 0x70, 0x63, 0x3a, 0xa1, 0xb3, 0xf3,
  0xa7, 0x5b, 0x0e, 0xff, 0xb7, 0x61, 0x11, 0x54,
  0x91, 0x99, 0xe5, 0x91, 0x32, 0x2d, 0xeb, 0x3f,
  0xd8, 0x3e, 0xf7, 0xd4, 0xcb, 0xd2, 0xa3, 0x41,
  0xc1, 0xee, 0xc6, 0x92, 0x13, 0xeb, 0x7f, 0x42,
  0x58, 0xf4, 0xd0, 0xb2, 0x74, 0x1d, 0x8e, 0x87,
  0x46, 0xcd, 0x14, 0xb8, 0x16, 0xad, 0xb5, 0xbd,
  0x0d, 0x6c, 0x95, 0x5a, 0x16, 0xbf, 0xe9, 0x53,
  0xda, 0xfb, 0xed, 0x83, 0x51, 0x67, 0xa9, 0x55,
  0xab, 0x54, 0x02, 0x95, 0x20, 0xa6, 0x68, 0x17,
  0x53, 0xa8, 0xea, 0x43, 0xe5, 0xb0, 0xa3, 0x02,
  0x81, 0x80, 0x67, 0x9c, 0x32, 0x83, 0x39, 0x57,
  0xff, 0x73, 0xb0, 0x89, 0x64, 0x8b, 0xd6, 0xf0,
  0x0a, 0x2d, 0xe2, 0xaf, 0x30, 0x1c, 0x2a, 0x97,
  0xf3, 0x90, 0x9a, 0xab, 0x9b, 0x0b, 0x1b, 0x43,
  0x79, 0xa0, 0xa7, 0x3d, 0xe7, 0xbe, 0x8d, 0x9c,
  0xeb, 0xdb, 0xad, 0x40, 0xdd, 0xa9, 0x00, 0x80,
  0xb8, 0xe1, 0xb3, 0xa1, 0x6c, 0x25, 0x92, 0xe4,
  0x33, 0xb2, 0xbe, 0xeb, 0x4d, 0x74, 0x26, 0x5f,
  0x37, 0x43, 0x9c, 0x6c, 0x17, 0x76, 0x0a, 0x81,
  0x20, 0x82, 0xa1, 0x48, 0x2c, 0x2d, 0x45, 0xdc,
  0x0f, 0x62, 0x43, 0x32, 0xbb, 0xeb, 0x59, 0x41,
  0xf9, 0xca, 0x58, 0xce, 0x4a, 0x66, 0x53, 0x54,
  0xc8, 0x28, 0x10, 0x1e, 0x08, 0x71, 0x16, 0xd8,
  0x02, 0x71, 0x41, 0x58, 0xd4, 0x56, 0xcc, 0xf5,
  0xb1, 0x31, 0xa3, 0xed, 0x00, 0x85, 0x09, 0xbf,
  0x35, 0x95, 0x41, 0x29, 0x40, 0x19, 0x83, 0x35,
  0x24, 0x69, 0x02, 0x81, 0x80, 0x55, 0x10, 0x0b,
  0xcc, 0x3b, 0xa9, 0x75, 0x3d, 0x16, 0xe1, 0xae,
  0x50, 0x76, 0x63, 0x94, 0x49, 0x4c, 0xad, 0x10,
  0xcb, 0x47, 0x68, 0x7c, 0xf0, 0xe5, 0xdc, 0xb8,
  0x6a, 0xab, 0x8e, 0xf7, 0x9f, 0x08, 0x2c, 0x1b,
  0x8a, 0xa2, 0xb9, 0x8f, 0xce, 0xec, 0x5e, 0x61,
  0xa8, 0xcd, 0x1c, 0x87, 0x60, 0x4a, 0xc3, 0x1a,
  0x5f, 0xdf, 0x87, 0x26, 0xc6, 0xcb, 0x7c, 0x69,
  0xe4, 0x8b, 0x01, 0x06, 0x59, 0x22, 0xfa, 0x34,
  0x4b, 0x81, 0x87, 0x3c, 0x03, 0x6d, 0x02, 0x0a,
  0x77, 0xe6, 0x15, 0xd8, 0xcf, 0xa7, 0x68, 0x26,
  0x6c, 0xfa, 0x2b, 0xd9, 0x83, 0x5a, 0x2d, 0x0c,
  0x3b, 0x70, 0x1c, 0xd4, 0x48, 0xbe, 0xa7, 0x0a,
  0xd9, 0xbe, 0xdc, 0xc3, 0x0c, 0x21, 0x33, 0xb3,
  0x66, 0xff, 0x1c, 0x1b, 0xc8, 0x96, 0x76, 0xe8,
  0x6f, 0x44, 0x74, 0xbc, 0x9b, 0x1c, 0x7d, 0xc8,
  0xac, 0x21, 0xa8, 0x6e, 0x37, 0x02, 0x81, 0x80,
  0x2c, 0x7c, 0xad, 0x1e, 0x75, 0xf6, 0x69, 0x1d,
  0xe7, 0xa6, 0xca, 0x74, 0x7d, 0x67, 0xc8, 0x65,
  0x28, 0x66, 0xc4, 0x43, 0xa6, 0xbd, 0x40, 0x57,
  0xae, 0xb7, 0x65, 0x2c, 0x52, 0xf9, 0xe4, 0xc7,
  0x81, 0x7b, 0x56, 0xa3, 0xd2, 0x0d, 0xe8, 0x33,
  0x70, 0xcf, 0x06, 0x84, 0xb3, 0x4e, 0x44, 0x50,
  0x75, 0x61, 0x96, 0x86, 0x4b, 0xb6, 0x2b, 0xad,
  0xf0, 0xad, 0x57, 0xd0, 0x37, 0x0d, 0x1d, 0x35,
  0x50, 0xcb, 0x69, 0x22, 0x39, 0x29, 0xb9, 0x3a,
  0xd3, 0x29, 0x23, 0x02, 0x60, 0xf7, 0xab, 0x30,
  0x40, 0xda, 0x8e, 0x4d, 0x45, 0x70, 0x26, 0xf4,
  0xa2, 0x0d, 0xd0, 0x64, 0x5d, 0x47, 0x3c, 0x18,
  0xf4, 0xd4, 0x52, 0x95, 0x00, 0xae, 0x84, 0x6b,
  0x47, 0xb2, 0x3c, 0x82, 0xd3, 0x72, 0x53, 0xde,
  0x72, 0x2c, 0xf7, 0xc1, 0x22, 0x36, 0xd9, 0x18,
  0x56, 0xfe, 0x39, 0x28, 0x33, 0xe0, 0xdb, 0x03 };

static const uint8_t kTestRSAPublicKey2_2048[] = {
  0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
  0x00, 0xa7, 0x00, 0x36, 0x60, 0x65, 0xdc, 0xbd,
  0x54, 0x5a, 0x2a, 0x40, 0xb4, 0xe1, 0x15, 0x94,
  0x58, 0x11, 0x4f, 0x94, 0x58, 0xdd, 0xde, 0xa7,
  0x1f, 0x3c, 0x2c, 0xe0, 0x88, 0x09, 0x29, 0x61,
  0x57, 0x67, 0x5e, 0x56, 0x7e, 0xee, 0x27, 0x8f,
  0x59, 0x34, 0x9a, 0x2a, 0xaa, 0x9d, 0xb4, 0x4e,
  0xfa, 0xa7, 0x6a, 0xd4, 0xc9, 0x7a, 0x53, 0xc1,
  0x4e, 0x9f, 0xe3, 0x34, 0xf7, 0x3d, 0xb7, 0xc9,
  0x10, 0x47, 0x4f, 0x28, 0xda, 0x3f, 0xce, 0x31,
  0x7b, 0xfd, 0x06, 0x10, 0xeb, 0xf7, 0xbe, 0x92,
  0xf9, 0xaf, 0xfb, 0x3e, 0x68, 0xda, 0xee, 0x1a,
  0x64, 0x4c, 0xf3, 0x29, 0xf2, 0x73, 0x9e, 0x39,
  0xd8, 0xf6, 0x6f, 0xd8, 0xb2, 0x80, 0x82, 0x71,
  0x8e, 0xb5, 0xa4, 0xf2, 0xc2, 0x3e, 0xcd, 0x0a,
  0xca, 0xb6, 0x04, 0xcd, 0x9a, 0x13, 0x8b, 0x54,
  0x73, 0x54, 0x25, 0x54, 0x8c, 0xbe, 0x98, 0x7a,
  0x67, 0xad, 0xda, 0xb3, 0x4e, 0xb3, 0xfa, 0x82,
  0xa8, 0x4a, 0x67, 0x98, 0x56, 0x57, 0x54, 0x71,
  0xcd, 0x12, 0x7f, 0xed, 0xa3, 0x01, 0xc0, 0x6a,
  0x8b, 0x24, 0x03, 0x96, 0x88, 0xbe, 0x97, 0x66,
  0x2a, 0xbc, 0x53, 0xc9, 0x83, 0x06, 0x51, 0x5a,
  0x88, 0x65, 0x13, 0x18, 0xe4, 0x3a, 0xed, 0x6b,
  0xf1, 0x61, 0x5b, 0x4c, 0xc8, 0x1e, 0xf4, 0xc2,
  0xae, 0x08, 0x5e, 0x2d, 0x5f, 0xf8, 0x12, 0x7f,
  0xa2, 0xfc, 0xbb, 0x21, 0x18, 0x30, 0xda, 0xfe,
  0x40, 0xfb, 0x01, 0xca, 0x2e, 0x37, 0x0e, 0xce,
  0xdd, 0x76, 0x87, 0x82, 0x46, 0x0b, 0x3a, 0x77,
  0x8f, 0xc0, 0x72, 0x07, 0x2c, 0x7f, 0x9d, 0x1e,
  0x86, 0x5b, 0xed, 0x27, 0x29, 0xdf, 0x03, 0x97,
  0x62, 0xef, 0x44, 0xd3, 0x5b, 0x3d, 0xdb, 0x9c,
  0x5e, 0x1b, 0x7b, 0x39, 0xb4, 0x0b, 0x6d, 0x04,
  0x6b, 0xbb, 0xbb, 0x2c, 0x5f, 0xcf, 0xb3, 0x7a,
  0x05, 0x02, 0x03, 0x01, 0x00, 0x01 };

static const uint8_t kTestPKCS1RSAPrivateKey3_2048[] = {
  0x30, 0x82, 0x04, 0xa4, 0x02, 0x01, 0x00, 0x02,
  0x82, 0x01, 0x01, 0x00, 0xa5, 0xd0, 0xd7, 0x3e,
  0x0e, 0x2d, 0xfb, 0x43, 0x51, 0x99, 0xea, 0x40,
  0x1e, 0x2d, 0x89, 0xe4, 0xa2, 0x3e, 0xfc, 0x51,
  0x3d, 0x0e, 0x83, 0xa7, 0xe0, 0xa5, 0x41, 0x04,
  0x1e, 0x14, 0xc5, 0xa7, 0x5c, 0x61, 0x36, 0x44,
  0xb3, 0x08, 0x05, 0x5b, 0x14, 0xde, 0x01, 0x0c,
  0x32, 0x3c, 0x9a, 0x91, 0x00, 0x50, 0xa8, 0x1d,
  0xcc, 0x9f, 0x8f, 0x35, 0xb7, 0xc2, 0x75, 0x08,
  0x32, 0x8b, 0x10, 0x3a, 0x86, 0xf9, 0xd7, 0x78,
  0xa3, 0x9d, 0x74, 0x10, 0xc6, 0x24, 0xb1, 0x7f,
  0xa5, 0xbf, 0x5f, 0xc2, 0xd7, 0x15, 0xa3, 0x1d,
  0xe0, 0x15, 0x6b, 0x1b, 0x0e, 0x38, 0xba, 0x34,
  0xbc, 0x95, 0x47, 0x94, 0x40, 0x70, 0xac, 0x99,
  0x1f, 0x0b, 0x8e, 0x56, 0x93, 0x36, 0x2b, 0x6d,
  0x04, 0xe7, 0x95, 0x1a, 0x37, 0xda, 0x16, 0x57,
  0x99, 0xee, 0x03, 0x68, 0x16, 0x31, 0xaa, 0xc3,
  0xb7, 0x92, 0x75, 0x53, 0xfc, 0xf6, 0x20, 0x55,
  0x44, 0xf8, 0xd4, 0x8d, 0x78, 0x15, 0xc7, 0x1a,
  0xb6, 0xde, 0x6c, 0xe8, 0x49, 0x5d, 0xaf, 0xa8,
  0x4e, 0x6f, 0x7c, 0xe2, 0x6a, 0x4c, 0xd5, 0xe7,
  0x8c, 0x8f, 0x0b, 0x5d, 0x3a, 0x09, 0xd6, 0xb3,
  0x44, 0xab, 0xe0, 0x35, 0x52, 0x7c, 0x66, 0x85,
  0xa4, 0x40, 0xd7, 0x20, 0xec, 0x24, 0x05, 0x06,
  0xd9, 0x84, 0x51, 0x5a, 0xd2, 0x38, 0xd5, 0x1d,
  0xea, 0x70, 0x2a, 0x21, 0xe6, 0x82, 0xfd, 0xa4,
  0x46, 0x1c, 0x4f, 0x59, 0x6e, 0x29, 0x3d, 0xae,
  0xb8, 0x8e, 0xee, 0x77, 0x1f, 0x15, 0x33, 0xcf,
  0x94, 0x1d, 0x87, 0x3c, 0x37, 0xc5, 0x89, 0xe8,
  0x7d, 0x85, 0xb3, 0xbc, 0xe8, 0x62, 0x6a, 0x84,
  0x7f, 0xfe, 0x9a, 0x85, 0x3f, 0x39, 0xe8, 0xaa,
  0x16, 0xa6, 0x8f, 0x87, 0x7f, 0xcb, 0xc1, 0xd6,
  0xf2, 0xec, 0x2b, 0xa7, 0xdd, 0x49, 0x98, 0x7b,
  0x6f, 0xdd, 0x69, 0x6d, 0x02, 0x03, 0x01, 0x00,
  0x01, 0x02, 0x82, 0x01, 0x00, 0x43, 0x8f, 0x19,
  0x83, 0xb1, 0x27, 0x4e, 0xee, 0x98, 0xba, 0xcb,
  0x54, 0xa0, 0x77, 0x11, 0x6d, 0xd4, 0x25, 0x31,
  0x8c, 0xb0, 0x01, 0xcf, 0xe6, 0x80, 0x83, 0x14,
  0x40, 0x67, 0x39, 0x33, 0x67, 0x03, 0x1e, 0xa0,
  0x8b, 0xd1, 0x1d, 0xfd, 0x80, 0xa4, 0xb9, 0xe7,
  0x57, 0x5e, 0xc8, 0x8e, 0x79, 0x71, 0xd5, 0x6b,
  0x09, 0xe9, 0x2b, 0x41, 0xa0, 0x33, 0x64, 0xc9,
  0x66, 0x33, 0xa1, 0xb1, 0x55, 0x07, 0x55, 0x98,
  0x53, 0x10, 0xe6, 0xc0, 0x39, 0x6d, 0x61, 0xd9,
  0xe8, 0x16, 0x52, 0x28, 0xe4, 0x2b, 0xda, 0x27,
  0x01, 0xaf, 0x21, 0x4a, 0xe8, 0x55, 0x1d, 0x0b,
  0xd1, 0x1c, 0xdc, 0xfd, 0xb3, 0x0b, 0xa6, 0x5c,
  0xcc, 0x6e, 0x77, 0xb8, 0xe0, 0xd1, 0x4e, 0x0a,
  0xd7, 0x7a, 0x5e, 0x18, 0xc3, 0xfb, 0xe9, 0xa1,
  0x9c, 0xc3, 0x9c, 0xd4, 0x4a, 0x7e, 0x70, 0x72,
  0x11, 0x18, 0x24, 0x56, 0x24, 0xdf, 0xf8, 0xba,
  0xac, 0x5b, 0x54, 0xd3, 0xc4, 0x65, 0x69, 0xc8,
  0x79, 0x94, 0x16, 0x88, 0x9a, 0x68, 0x1c, 0xbc,
  0xd4, 0xca, 0xec, 0x5e, 0x07, 0x4a, 0xc9, 0x54,
  0x7a, 0x4b, 0xdb, 0x19, 0x88, 0xf6, 0xbe, 0x50,
  0x9d, 0x9e, 0x9d, 0x88, 0x5b, 0x4a, 0x23, 0x86,
  0x2b, 0xa9, 0xa6, 0x6c, 0x70, 0x7d, 0xe1, 0x11,
  0xba, 0xbf, 0x03, 0x2e, 0xf1, 0x46, 0x7e, 0x1b,
  0xed, 0x06, 0x11, 0x57, 0xad, 0x4a, 0xcb, 0xe5,
  0xb1, 0x11, 0x05, 0x0a, 0x30, 0xb1, 0x73, 0x79,
  0xcd, 0x7a, 0x04, 0xcc, 0x70, 0xe9, 0x95, 0xe4,
  0x27, 0xc2, 0xd5, 0x2d, 0x92, 0x44, 0xdf, 0xb4,
  0x94, 0xa8, 0x73, 0xa1, 0x4a, 0xc3, 0xcc, 0xc4,
  0x0e, 0x8d, 0xa1, 0x6a, 0xc2, 0xd8, 0x03, 0x7f,
  0xfa, 0xa7, 0x76, 0x0d, 0xad, 0x87, 0x88, 0xa0,
  0x77, 0xaf, 0x3b, 0x23, 0xd1, 0x66, 0x0b, 0x31,
  0x2b, 0xaf, 0xef, 0xd5, 0x41, 0x02, 0x81, 0x81,
  0x00, 0xdb, 0xc1, 0xe7, 0xdd, 0xba, 0x3c, 0x1f,
  0x9c, 0x64, 0xca, 0xa0, 0x63, 0xdb, 0xd2, 0x47,
  0x5c, 0x6e, 0x8a, 0xa3, 0x16, 0xd5, 0xda, 0xc2,
  0x25, 0x64, 0x0a, 0x02, 0xbc, 0x7d, 0x7f, 0x50,
  0xab, 0xe0, 0x66, 0x03, 0x53, 0x7d, 0x77, 0x6d,
  0x6c, 0x61, 0x58, 0x09, 0x73, 0xcd, 0x18, 0xe9,
  0x53, 0x0b, 0x5c, 0xa2, 0x71, 0x14, 0x02, 0xfd,
  0x55, 0xda, 0xe9, 0x77, 0x24, 0x7c, 0x2a, 0x4e,
  0xb9, 0xd9, 0x5d, 0x58, 0xf6, 0x26, 0xd0, 0xd8,
  0x3d, 0xcf, 0x8c, 0x89, 0x65, 0x6c, 0x35, 0x19,
  0xb6, 0x63, 0xff, 0xa0, 0x71, 0x49, 0xcd, 0x6d,
  0x5b, 0x3d, 0x8f, 0xea, 0x6f, 0xa9, 0xba, 0x43,
  0xe5, 0xdd, 0x39, 0x3a, 0x78, 0x8f, 0x07, 0xb8,
  0xab, 0x58, 0x07, 0xb7, 0xd2, 0xf8, 0x07, 0x02,
  0x9b, 0x79, 0x26, 0x32, 0x22, 0x38, 0x91, 0x01,
  0x90, 0x81, 0x29, 0x94, 0xad, 0x77, 0xeb, 0x86,
  0xb9, 0x02, 0x81, 0x81, 0x00, 0xc1, 0x29, 0x88,
  0xbd, 0x96, 0x31, 0x33, 0x7b, 0x77, 0x5d, 0x32,
  0x12, 0x5e, 0xdf, 0x28, 0x0c, 0x96, 0x0d, 0xa8,
  0x22, 0xdf, 0xd3, 0x35, 0xd7, 0xb0, 0x41, 0xcb,
  0xe7, 0x94, 0x8a, 0xa4, 0xed, 0xd2, 0xfb, 0xd2,
  0xf3, 0xf2, 0x95, 0xff, 0xd8, 0x33, 0x3f, 0x8c,
  0xd7, 0x65, 0xe4, 0x0c, 0xcc, 0xfe, 0x32, 0x66,
  0xfa, 0x50, 0xe2, 0xcf, 0xf0, 0xbe, 0x05, 0xb1,
  0xbc, 0xbe, 0x44, 0x09, 0xb4, 0xfe, 0x95, 0x06,
  0x18, 0xd7, 0x59, 0xc6, 0xef, 0x2d, 0x22, 0xa0,
  0x73, 0x5e, 0x77, 0xdf, 0x8d, 0x09, 0x2c, 0xb8,
  0xcc, 0xeb, 0x10, 0x4d, 0xa7, 0xd0, 0x4b, 0x46,
  0xba, 0x7d, 0x8b, 0x6a, 0x55, 0x47, 0x55, 0xd3,
  0xd7, 0xb1, 0x88, 0xfd, 0x27, 0x3e, 0xf9, 0x5b,
  0x7b, 0xae, 0x6d, 0x08, 0x9f, 0x0c, 0x2a, 0xe1,
  0xdd, 0xb9, 0xe3, 0x55, 0x13, 0x55, 0xa3, 0x6d,
  0x06, 0xbb, 0xe0, 0x1e, 0x55, 0x02, 0x81, 0x80,
  0x61, 0x73, 0x3d, 0x64, 0xff, 0xdf, 0x05, 0x8d,
  0x8e, 0xcc, 0xa4, 0x0f, 0x64, 0x3d, 0x7d, 0x53,
  0xa9, 0xd9, 0x64, 0xb5, 0x0d, 0xa4, 0x72, 0x8f,
  0xae, 0x2b, 0x1a, 0x47, 0x87, 0xc7, 0x5b, 0x78,
  0xbc, 0x8b, 0xc0, 0x51, 0xd7, 0xc3, 0x8c, 0x0c,
  0x91, 0xa6, 0x3e, 0x9a, 0xd1, 0x8a, 0x88, 0x7d,
  0x40, 0xfe, 0x95, 0x32, 0x5b, 0xd3, 0x6f, 0x90,
  0x11, 0x01, 0x92, 0xc9, 0xe5, 0x1d, 0xc5, 0xc7,
  0x78, 0x72, 0x82, 0xae, 0xb5, 0x4b, 0xcb, 0x78,
  0xad, 0x7e, 0xfe, 0xb6, 0xb1, 0x23, 0x63, 0x01,
  0x94, 0x9a, 0x99, 0x05, 0x63, 0xda, 0xea, 0xf1,
  0x98, 0xfd, 0x26, 0xd2, 0xd9, 0x8b, 0x35, 0xec,
  0xcb, 0x0b, 0x43, 0xb8, 0x8e, 0x84, 0xb8, 0x09,
  0x93, 0x81, 0xe8, 0xac, 0x6f, 0x3c, 0x7c, 0x95,
  0x81, 0x45, 0xc4, 0xd9, 0x94, 0x08, 0x09, 0x8f,
  0x91, 0x17, 0x65, 0x4c, 0xff, 0x6e, 0xbc, 0x51,
  0x02, 0x81, 0x81, 0x00, 0xc1, 0x0d, 0x9d, 0xd8,
  0xbd, 0xaf, 0x56, 0xe0, 0xe3, 0x1f, 0x85, 0xd7,
  0xce, 0x72, 0x02, 0x38, 0xf2, 0x0f, 0x9c, 0x27,
  0x9e, 0xc4, 0x1d, 0x60, 0x00, 0x8d, 0x02, 0x19,
  0xe5, 0xdf, 0xdb, 0x8e, 0xc5, 0xfb, 0x61, 0x8e,
  0xe6, 0xb8, 0xfc, 0x07, 0x3c, 0xd1, 0x1b, 0x16,
  0x7c, 0x83, 0x3c, 0x37, 0xf5, 0x26, 0xb2, 0xbd,
  0x22, 0xf2, 0x4d, 0x19, 0x33, 0x11, 0xc5, 0xdd,
  0xf9, 0xdb, 0x4e, 0x48, 0x52, 0xd8, 0xe6, 0x4b,
  0x15, 0x90, 0x68, 0xbe, 0xca, 0xc1, 0x7c, 0xd3,
  0x51, 0x6b, 0x45, 0x46, 0x54, 0x11, 0x1a, 0x71,
  0xd3, 0xcd, 0x6b, 0x8f, 0x79, 0x22, 0x83, 0x02,
  0x08, 0x4f, 0xba, 0x6a, 0x98, 0xed, 0x32, 0xd8,
  0xb4, 0x5b, 0x51, 0x88, 0x53, 0xec, 0x2c, 0x7e,
  0xa4, 0x89, 0xdc, 0xbf, 0xf9, 0x0d, 0x32, 0xc8,
  0xc3, 0xec, 0x6d, 0x2e, 0xf1, 0xbc, 0x70, 0x4e,
  0xf6, 0x9e, 0xbc, 0x31, 0x02, 0x81, 0x81, 0x00,
  0xd3, 0x35, 0x1b, 0x19, 0x75, 0x3f, 0x61, 0xf2,
  0x55, 0x03, 0xce, 0x25, 0xa9, 0xdf, 0x0c, 0x0a,
  0x3b, 0x47, 0x42, 0xdc, 0x38, 0x4b, 0x13, 0x4d,
  0x1f, 0x86, 0x58, 0x4f, 0xd8, 0xee, 0xfa, 0x76,
  0x15, 0xfb, 0x6e, 0x55, 0x31, 0xf2, 0xd2, 0x62,
  0x32, 0xa5, 0xc4, 0x23, 0x5e, 0x08, 0xa9, 0x83,
  0x07, 0xac, 0x8c, 0xa3, 0x7e, 0x18, 0xc0, 0x1c,
  0x57, 0x63, 0x8d, 0x05, 0x17, 0x47, 0x1b, 0xd3,
  0x74, 0x73, 0x20, 0x04, 0xfb, 0xc8, 0x1a, 0x43,
  0x04, 0x36, 0xc8, 0x19, 0xbe, 0xdc, 0xa6, 0xe5,
  0x0f, 0x25, 0x62, 0x24, 0x96, 0x92, 0xb6, 0xb3,
  0x97, 0xad, 0x57, 0x9a, 0x90, 0x37, 0x4e, 0x31,
  0x44, 0x74, 0xfa, 0x7c, 0xb4, 0xea, 0xfc, 0x15,
  0xa7, 0xb0, 0x51, 0xcc, 0xee, 0x1e, 0xed, 0x5b,
  0x98, 0x18, 0x0e, 0x65, 0xb6, 0x4b, 0x69, 0x0b,
  0x21, 0xdc, 0x86, 0x17, 0x6e, 0xc8, 0xee, 0x24 };

// 2048 bit RSA key in PKCS#8 PrivateKeyInfo
static const uint8_t kTestRSAPKCS8PrivateKeyInfo3_2048[] = {
  0x30, 0x82, 0x04, 0xbe, 0x02, 0x01, 0x00, 0x30,
  0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
  0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82,
  0x04, 0xa8, 0x30, 0x82, 0x04, 0xa4, 0x02, 0x01,
  0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0xa5, 0xd0,
  0xd7, 0x3e, 0x0e, 0x2d, 0xfb, 0x43, 0x51, 0x99,
  0xea, 0x40, 0x1e, 0x2d, 0x89, 0xe4, 0xa2, 0x3e,
  0xfc, 0x51, 0x3d, 0x0e, 0x83, 0xa7, 0xe0, 0xa5,
  0x41, 0x04, 0x1e, 0x14, 0xc5, 0xa7, 0x5c, 0x61,
  0x36, 0x44, 0xb3, 0x08, 0x05, 0x5b, 0x14, 0xde,
  0x01, 0x0c, 0x32, 0x3c, 0x9a, 0x91, 0x00, 0x50,
  0xa8, 0x1d, 0xcc, 0x9f, 0x8f, 0x35, 0xb7, 0xc2,
  0x75, 0x08, 0x32, 0x8b, 0x10, 0x3a, 0x86, 0xf9,
  0xd7, 0x78, 0xa3, 0x9d, 0x74, 0x10, 0xc6, 0x24,
  0xb1, 0x7f, 0xa5, 0xbf, 0x5f, 0xc2, 0xd7, 0x15,
  0xa3, 0x1d, 0xe0, 0x15, 0x6b, 0x1b, 0x0e, 0x38,
  0xba, 0x34, 0xbc, 0x95, 0x47, 0x94, 0x40, 0x70,
  0xac, 0x99, 0x1f, 0x0b, 0x8e, 0x56, 0x93, 0x36,
  0x2b, 0x6d, 0x04, 0xe7, 0x95, 0x1a, 0x37, 0xda,
  0x16, 0x57, 0x99, 0xee, 0x03, 0x68, 0x16, 0x31,
  0xaa, 0xc3, 0xb7, 0x92, 0x75, 0x53, 0xfc, 0xf6,
  0x20, 0x55, 0x44, 0xf8, 0xd4, 0x8d, 0x78, 0x15,
  0xc7, 0x1a, 0xb6, 0xde, 0x6c, 0xe8, 0x49, 0x5d,
  0xaf, 0xa8, 0x4e, 0x6f, 0x7c, 0xe2, 0x6a, 0x4c,
  0xd5, 0xe7, 0x8c, 0x8f, 0x0b, 0x5d, 0x3a, 0x09,
  0xd6, 0xb3, 0x44, 0xab, 0xe0, 0x35, 0x52, 0x7c,
  0x66, 0x85, 0xa4, 0x40, 0xd7, 0x20, 0xec, 0x24,
  0x05, 0x06, 0xd9, 0x84, 0x51, 0x5a, 0xd2, 0x38,
  0xd5, 0x1d, 0xea, 0x70, 0x2a, 0x21, 0xe6, 0x82,
  0xfd, 0xa4, 0x46, 0x1c, 0x4f, 0x59, 0x6e, 0x29,
  0x3d, 0xae, 0xb8, 0x8e, 0xee, 0x77, 0x1f, 0x15,
  0x33, 0xcf, 0x94, 0x1d, 0x87, 0x3c, 0x37, 0xc5,
  0x89, 0xe8, 0x7d, 0x85, 0xb3, 0xbc, 0xe8, 0x62,
  0x6a, 0x84, 0x7f, 0xfe, 0x9a, 0x85, 0x3f, 0x39,
  0xe8, 0xaa, 0x16, 0xa6, 0x8f, 0x87, 0x7f, 0xcb,
  0xc1, 0xd6, 0xf2, 0xec, 0x2b, 0xa7, 0xdd, 0x49,
  0x98, 0x7b, 0x6f, 0xdd, 0x69, 0x6d, 0x02, 0x03,
  0x01, 0x00, 0x01, 0x02, 0x82, 0x01, 0x00, 0x43,
  0x8f, 0x19, 0x83, 0xb1, 0x27, 0x4e, 0xee, 0x98,
  0xba, 0xcb, 0x54, 0xa0, 0x77, 0x11, 0x6d, 0xd4,
  0x25, 0x31, 0x8c, 0xb0, 0x01, 0xcf, 0xe6, 0x80,
  0x83, 0x14, 0x40, 0x67, 0x39, 0x33, 0x67, 0x03,
  0x1e, 0xa0, 0x8b, 0xd1, 0x1d, 0xfd, 0x80, 0xa4,
  0xb9, 0xe7, 0x57, 0x5e, 0xc8, 0x8e, 0x79, 0x71,
  0xd5, 0x6b, 0x09, 0xe9, 0x2b, 0x41, 0xa0, 0x33,
  0x64, 0xc9, 0x66, 0x33, 0xa1, 0xb1, 0x55, 0x07,
  0x55, 0x98, 0x53, 0x10, 0xe6, 0xc0, 0x39, 0x6d,
  0x61, 0xd9, 0xe8, 0x16, 0x52, 0x28, 0xe4, 0x2b,
  0xda, 0x27, 0x01, 0xaf, 0x21, 0x4a, 0xe8, 0x55,
  0x1d, 0x0b, 0xd1, 0x1c, 0xdc, 0xfd, 0xb3, 0x0b,
  0xa6, 0x5c, 0xcc, 0x6e, 0x77, 0xb8, 0xe0, 0xd1,
  0x4e, 0x0a, 0xd7, 0x7a, 0x5e, 0x18, 0xc3, 0xfb,
  0xe9, 0xa1, 0x9c, 0xc3, 0x9c, 0xd4, 0x4a, 0x7e,
  0x70, 0x72, 0x11, 0x18, 0x24, 0x56, 0x24, 0xdf,
  0xf8, 0xba, 0xac, 0x5b, 0x54, 0xd3, 0xc4, 0x65,
  0x69, 0xc8, 0x79, 0x94, 0x16, 0x88, 0x9a, 0x68,
  0x1c, 0xbc, 0xd4, 0xca, 0xec, 0x5e, 0x07, 0x4a,
  0xc9, 0x54, 0x7a, 0x4b, 0xdb, 0x19, 0x88, 0xf6,
  0xbe, 0x50, 0x9d, 0x9e, 0x9d, 0x88, 0x5b, 0x4a,
  0x23, 0x86, 0x2b, 0xa9, 0xa6, 0x6c, 0x70, 0x7d,
  0xe1, 0x11, 0xba, 0xbf, 0x03, 0x2e, 0xf1, 0x46,
  0x7e, 0x1b, 0xed, 0x06, 0x11, 0x57, 0xad, 0x4a,
  0xcb, 0xe5, 0xb1, 0x11, 0x05, 0x0a, 0x30, 0xb1,
  0x73, 0x79, 0xcd, 0x7a, 0x04, 0xcc, 0x70, 0xe9,
  0x95, 0xe4, 0x27, 0xc2, 0xd5, 0x2d, 0x92, 0x44,
  0xdf, 0xb4, 0x94, 0xa8, 0x73, 0xa1, 0x4a, 0xc3,
  0xcc, 0xc4, 0x0e, 0x8d, 0xa1, 0x6a, 0xc2, 0xd8,
  0x03, 0x7f, 0xfa, 0xa7, 0x76, 0x0d, 0xad, 0x87,
  0x88, 0xa0, 0x77, 0xaf, 0x3b, 0x23, 0xd1, 0x66,
  0x0b, 0x31, 0x2b, 0xaf, 0xef, 0xd5, 0x41, 0x02,
  0x81, 0x81, 0x00, 0xdb, 0xc1, 0xe7, 0xdd, 0xba,
  0x3c, 0x1f, 0x9c, 0x64, 0xca, 0xa0, 0x63, 0xdb,
  0xd2, 0x47, 0x5c, 0x6e, 0x8a, 0xa3, 0x16, 0xd5,
  0xda, 0xc2, 0x25, 0x64, 0x0a, 0x02, 0xbc, 0x7d,
  0x7f, 0x50, 0xab, 0xe0, 0x66, 0x03, 0x53, 0x7d,
  0x77, 0x6d, 0x6c, 0x61, 0x58, 0x09, 0x73, 0xcd,
  0x18, 0xe9, 0x53, 0x0b, 0x5c, 0xa2, 0x71, 0x14,
  0x02, 0xfd, 0x55, 0xda, 0xe9, 0x77, 0x24, 0x7c,
  0x2a, 0x4e, 0xb9, 0xd9, 0x5d, 0x58, 0xf6, 0x26,
  0xd0, 0xd8, 0x3d, 0xcf, 0x8c, 0x89, 0x65, 0x6c,
  0x35, 0x19, 0xb6, 0x63, 0xff, 0xa0, 0x71, 0x49,
  0xcd, 0x6d, 0x5b, 0x3d, 0x8f, 0xea, 0x6f, 0xa9,
  0xba, 0x43, 0xe5, 0xdd, 0x39, 0x3a, 0x78, 0x8f,
  0x07, 0xb8, 0xab, 0x58, 0x07, 0xb7, 0xd2, 0xf8,
  0x07, 0x02, 0x9b, 0x79, 0x26, 0x32, 0x22, 0x38,
  0x91, 0x01, 0x90, 0x81, 0x29, 0x94, 0xad, 0x77,
  0xeb, 0x86, 0xb9, 0x02, 0x81, 0x81, 0x00, 0xc1,
  0x29, 0x88, 0xbd, 0x96, 0x31, 0x33, 0x7b, 0x77,
  0x5d, 0x32, 0x12, 0x5e, 0xdf, 0x28, 0x0c, 0x96,
  0x0d, 0xa8, 0x22, 0xdf, 0xd3, 0x35, 0xd7, 0xb0,
  0x41, 0xcb, 0xe7, 0x94, 0x8a, 0xa4, 0xed, 0xd2,
  0xfb, 0xd2, 0xf3, 0xf2, 0x95, 0xff, 0xd8, 0x33,
  0x3f, 0x8c, 0xd7, 0x65, 0xe4, 0x0c, 0xcc, 0xfe,
  0x32, 0x66, 0xfa, 0x50, 0xe2, 0xcf, 0xf0, 0xbe,
  0x05, 0xb1, 0xbc, 0xbe, 0x44, 0x09, 0xb4, 0xfe,
  0x95, 0x06, 0x18, 0xd7, 0x59, 0xc6, 0xef, 0x2d,
  0x22, 0xa0, 0x73, 0x5e, 0x77, 0xdf, 0x8d, 0x09,
  0x2c, 0xb8, 0xcc, 0xeb, 0x10, 0x4d, 0xa7, 0xd0,
  0x4b, 0x46, 0xba, 0x7d, 0x8b, 0x6a, 0x55, 0x47,
  0x55, 0xd3, 0xd7, 0xb1, 0x88, 0xfd, 0x27, 0x3e,
  0xf9, 0x5b, 0x7b, 0xae, 0x6d, 0x08, 0x9f, 0x0c,
  0x2a, 0xe1, 0xdd, 0xb9, 0xe3, 0x55, 0x13, 0x55,
  0xa3, 0x6d, 0x06, 0xbb, 0xe0, 0x1e, 0x55, 0x02,
  0x81, 0x80, 0x61, 0x73, 0x3d, 0x64, 0xff, 0xdf,
  0x05, 0x8d, 0x8e, 0xcc, 0xa4, 0x0f, 0x64, 0x3d,
  0x7d, 0x53, 0xa9, 0xd9, 0x64, 0xb5, 0x0d, 0xa4,
  0x72, 0x8f, 0xae, 0x2b, 0x1a, 0x47, 0x87, 0xc7,
  0x5b, 0x78, 0xbc, 0x8b, 0xc0, 0x51, 0xd7, 0xc3,
  0x8c, 0x0c, 0x91, 0xa6, 0x3e, 0x9a, 0xd1, 0x8a,
  0x88, 0x7d, 0x40, 0xfe, 0x95, 0x32, 0x5b, 0xd3,
  0x6f, 0x90, 0x11, 0x01, 0x92, 0xc9, 0xe5, 0x1d,
  0xc5, 0xc7, 0x78, 0x72, 0x82, 0xae, 0xb5, 0x4b,
  0xcb, 0x78, 0xad, 0x7e, 0xfe, 0xb6, 0xb1, 0x23,
  0x63, 0x01, 0x94, 0x9a, 0x99, 0x05, 0x63, 0xda,
  0xea, 0xf1, 0x98, 0xfd, 0x26, 0xd2, 0xd9, 0x8b,
  0x35, 0xec, 0xcb, 0x0b, 0x43, 0xb8, 0x8e, 0x84,
  0xb8, 0x09, 0x93, 0x81, 0xe8, 0xac, 0x6f, 0x3c,
  0x7c, 0x95, 0x81, 0x45, 0xc4, 0xd9, 0x94, 0x08,
  0x09, 0x8f, 0x91, 0x17, 0x65, 0x4c, 0xff, 0x6e,
  0xbc, 0x51, 0x02, 0x81, 0x81, 0x00, 0xc1, 0x0d,
  0x9d, 0xd8, 0xbd, 0xaf, 0x56, 0xe0, 0xe3, 0x1f,
  0x85, 0xd7, 0xce, 0x72, 0x02, 0x38, 0xf2, 0x0f,
  0x9c, 0x27, 0x9e, 0xc4, 0x1d, 0x60, 0x00, 0x8d,
  0x02, 0x19, 0xe5, 0xdf, 0xdb, 0x8e, 0xc5, 0xfb,
  0x61, 0x8e, 0xe6, 0xb8, 0xfc, 0x07, 0x3c, 0xd1,
  0x1b, 0x16, 0x7c, 0x83, 0x3c, 0x37, 0xf5, 0x26,
  0xb2, 0xbd, 0x22, 0xf2, 0x4d, 0x19, 0x33, 0x11,
  0xc5, 0xdd, 0xf9, 0xdb, 0x4e, 0x48, 0x52, 0xd8,
  0xe6, 0x4b, 0x15, 0x90, 0x68, 0xbe, 0xca, 0xc1,
  0x7c, 0xd3, 0x51, 0x6b, 0x45, 0x46, 0x54, 0x11,
  0x1a, 0x71, 0xd3, 0xcd, 0x6b, 0x8f, 0x79, 0x22,
  0x83, 0x02, 0x08, 0x4f, 0xba, 0x6a, 0x98, 0xed,
  0x32, 0xd8, 0xb4, 0x5b, 0x51, 0x88, 0x53, 0xec,
  0x2c, 0x7e, 0xa4, 0x89, 0xdc, 0xbf, 0xf9, 0x0d,
  0x32, 0xc8, 0xc3, 0xec, 0x6d, 0x2e, 0xf1, 0xbc,
  0x70, 0x4e, 0xf6, 0x9e, 0xbc, 0x31, 0x02, 0x81,
  0x81, 0x00, 0xd3, 0x35, 0x1b, 0x19, 0x75, 0x3f,
  0x61, 0xf2, 0x55, 0x03, 0xce, 0x25, 0xa9, 0xdf,
  0x0c, 0x0a, 0x3b, 0x47, 0x42, 0xdc, 0x38, 0x4b,
  0x13, 0x4d, 0x1f, 0x86, 0x58, 0x4f, 0xd8, 0xee,
  0xfa, 0x76, 0x15, 0xfb, 0x6e, 0x55, 0x31, 0xf2,
  0xd2, 0x62, 0x32, 0xa5, 0xc4, 0x23, 0x5e, 0x08,
  0xa9, 0x83, 0x07, 0xac, 0x8c, 0xa3, 0x7e, 0x18,
  0xc0, 0x1c, 0x57, 0x63, 0x8d, 0x05, 0x17, 0x47,
  0x1b, 0xd3, 0x74, 0x73, 0x20, 0x04, 0xfb, 0xc8,
  0x1a, 0x43, 0x04, 0x36, 0xc8, 0x19, 0xbe, 0xdc,
  0xa6, 0xe5, 0x0f, 0x25, 0x62, 0x24, 0x96, 0x92,
  0xb6, 0xb3, 0x97, 0xad, 0x57, 0x9a, 0x90, 0x37,
  0x4e, 0x31, 0x44, 0x74, 0xfa, 0x7c, 0xb4, 0xea,
  0xfc, 0x15, 0xa7, 0xb0, 0x51, 0xcc, 0xee, 0x1e,
  0xed, 0x5b, 0x98, 0x18, 0x0e, 0x65, 0xb6, 0x4b,
  0x69, 0x0b, 0x21, 0xdc, 0x86, 0x17, 0x6e, 0xc8,
  0xee, 0x24 };

static const uint8_t kTestRSAPublicKey3_2048[] = {
  0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
  0x00, 0xa5, 0xd0, 0xd7, 0x3e, 0x0e, 0x2d, 0xfb,
  0x43, 0x51, 0x99, 0xea, 0x40, 0x1e, 0x2d, 0x89,
  0xe4, 0xa2, 0x3e, 0xfc, 0x51, 0x3d, 0x0e, 0x83,
  0xa7, 0xe0, 0xa5, 0x41, 0x04, 0x1e, 0x14, 0xc5,
  0xa7, 0x5c, 0x61, 0x36, 0x44, 0xb3, 0x08, 0x05,
  0x5b, 0x14, 0xde, 0x01, 0x0c, 0x32, 0x3c, 0x9a,
  0x91, 0x00, 0x50, 0xa8, 0x1d, 0xcc, 0x9f, 0x8f,
  0x35, 0xb7, 0xc2, 0x75, 0x08, 0x32, 0x8b, 0x10,
  0x3a, 0x86, 0xf9, 0xd7, 0x78, 0xa3, 0x9d, 0x74,
  0x10, 0xc6, 0x24, 0xb1, 0x7f, 0xa5, 0xbf, 0x5f,
  0xc2, 0xd7, 0x15, 0xa3, 0x1d, 0xe0, 0x15, 0x6b,
  0x1b, 0x0e, 0x38, 0xba, 0x34, 0xbc, 0x95, 0x47,
  0x94, 0x40, 0x70, 0xac, 0x99, 0x1f, 0x0b, 0x8e,
  0x56, 0x93, 0x36, 0x2b, 0x6d, 0x04, 0xe7, 0x95,
  0x1a, 0x37, 0xda, 0x16, 0x57, 0x99, 0xee, 0x03,
  0x68, 0x16, 0x31, 0xaa, 0xc3, 0xb7, 0x92, 0x75,
  0x53, 0xfc, 0xf6, 0x20, 0x55, 0x44, 0xf8, 0xd4,
  0x8d, 0x78, 0x15, 0xc7, 0x1a, 0xb6, 0xde, 0x6c,
  0xe8, 0x49, 0x5d, 0xaf, 0xa8, 0x4e, 0x6f, 0x7c,
  0xe2, 0x6a, 0x4c, 0xd5, 0xe7, 0x8c, 0x8f, 0x0b,
  0x5d, 0x3a, 0x09, 0xd6, 0xb3, 0x44, 0xab, 0xe0,
  0x35, 0x52, 0x7c, 0x66, 0x85, 0xa4, 0x40, 0xd7,
  0x20, 0xec, 0x24, 0x05, 0x06, 0xd9, 0x84, 0x51,
  0x5a, 0xd2, 0x38, 0xd5, 0x1d, 0xea, 0x70, 0x2a,
  0x21, 0xe6, 0x82, 0xfd, 0xa4, 0x46, 0x1c, 0x4f,
  0x59, 0x6e, 0x29, 0x3d, 0xae, 0xb8, 0x8e, 0xee,
  0x77, 0x1f, 0x15, 0x33, 0xcf, 0x94, 0x1d, 0x87,
  0x3c, 0x37, 0xc5, 0x89, 0xe8, 0x7d, 0x85, 0xb3,
  0xbc, 0xe8, 0x62, 0x6a, 0x84, 0x7f, 0xfe, 0x9a,
  0x85, 0x3f, 0x39, 0xe8, 0xaa, 0x16, 0xa6, 0x8f,
  0x87, 0x7f, 0xcb, 0xc1, 0xd6, 0xf2, 0xec, 0x2b,
  0xa7, 0xdd, 0x49, 0x98, 0x7b, 0x6f, 0xdd, 0x69,
  0x6d, 0x02, 0x03, 0x01, 0x00, 0x01 };

static void dump_openssl_error() {
  while (unsigned long err = ERR_get_error()) {
    char buffer[120];
    cout << "openssl error -- " << ERR_error_string(err, buffer) << "\n";
  }
}

class Session {
 public:
  Session() : valid_(false), open_(false) {}

  Session(string sname) : valid_(true), open_(false), sname_(sname),
                          mac_key_server_(wvcdm::MAC_KEY_SIZE),
                          mac_key_client_(wvcdm::MAC_KEY_SIZE),
                          enc_key_(wvcdm::KEY_SIZE), public_rsa_(0) {}

  bool isValid() { return valid_; }
  bool isOpen() { return open_; }
  bool successStatus() { return (OEMCrypto_SUCCESS == session_status_); }
  OEMCryptoResult getStatus() { return session_status_; }
  uint32_t get_nonce() { return nonce_; }

  uint32_t session_id() { return (uint32_t)session_id_; }
  void set_session_id(uint32_t newsession) {
    session_id_ = (OEMCrypto_SESSION)newsession;
  }

  void open() {
    EXPECT_TRUE(valid_);
    EXPECT_TRUE(!open_);
    session_status_ = OEMCrypto_OpenSession(&session_id_);
    if (OEMCrypto_SUCCESS == session_status_) {
      open_ = true;
    }
  }

  void close() {
    EXPECT_TRUE(valid_);
    session_status_ = OEMCrypto_CloseSession(session_id_);
    if (OEMCrypto_SUCCESS == session_status_) {
      open_ = false;
    }
  }

  void GenerateNonce(uint32_t* nonce) {
    ASSERT_EQ(OEMCrypto_SUCCESS,
              OEMCrypto_GenerateNonce(session_id(), nonce));
  }

  void GenerateDerivedKeys() {
    GenerateNonce(&nonce_);
    vector<uint8_t> mac_context = wvcdm::a2b_hex(
        "41555448454e5449434154494f4e000a4c08001248000000020000101907d9ff"
        "de13aa95c122678053362136bdf8408f8276e4c2d87ec52b61aa1b9f646e5873"
        "4930acebe899b3e464189a14a87202fb02574e70640bd22ef44b2d7e3912250a"
        "230a14080112100915007caa9b5931b76a3a85f046523e10011a093938373635"
        "34333231180120002a0c31383836373837343035000000000100");
    vector<uint8_t> enc_context = wvcdm::a2b_hex(
        "454e4352595054494f4e000a4c08001248000000020000101907d9ffde13aa95"
        "c122678053362136bdf8408f8276e4c2d87ec52b61aa1b9f646e58734930aceb"
        "e899b3e464189a14a87202fb02574e70640bd22ef44b2d7e3912250a230a1408"
        "0112100915007caa9b5931b76a3a85f046523e10011a09393837363534333231"
        "180120002a0c31383836373837343035000000000080");
    ASSERT_EQ(OEMCrypto_SUCCESS,
              OEMCrypto_GenerateDerivedKeys(
                  session_id(),
                  &mac_context[0], mac_context.size(),
                  &enc_context[0], enc_context.size()));
    mac_key_server_ = wvcdm::a2b_hex(
        "9D41F0A77A76E071841C33B06104D106641421E651FBE55F0AED453CDA7713AC");
    mac_key_client_ = wvcdm::a2b_hex(
        "125283F299AF42C191E1A989846B388BB16A6E50B2F67D4F876A3C1F662CD5C8");
    enc_key_ = wvcdm::a2b_hex("D0BFC35DA9E33436E81C4229E78CB9F4");
  }

  void LoadTestKeys(uint32_t duration, uint32_t control, uint32_t nonce) {
    MessageData data;
    FillSimpleMessage(&data, duration, control, nonce);
    MessageData encrypted;
    EncryptMessage(data, &encrypted);
    std::vector<uint8_t> signature;
    ServerSignMessage(encrypted, &signature);
    OEMCrypto_KeyObject key_array[kNumKeys];

    const uint8_t* message_ptr = reinterpret_cast<const uint8_t*>(&encrypted);
    FillKeyArray(encrypted, key_array);
    ASSERT_EQ(OEMCrypto_SUCCESS,
              OEMCrypto_LoadKeys(session_id(), message_ptr, sizeof(encrypted),
                                 &signature[0], signature.size(),
                                 encrypted.mac_key_iv, encrypted.mac_keys,
                                 kNumKeys, key_array));
    // Update new generated keys.
    memcpy(&mac_key_server_[0], data.mac_keys, wvcdm::MAC_KEY_SIZE);
    memcpy(&mac_key_client_[0], data.mac_keys+wvcdm::MAC_KEY_SIZE,
           wvcdm::MAC_KEY_SIZE);
  }

  void RefreshTestKeys(const int key_count, uint32_t control_bits, uint32_t nonce,
                       bool expect_good) {
    MessageData data;

    FillRefreshMessage(&data, key_count, control_bits, nonce);

    std::vector<uint8_t> signature;
    ServerSignMessage(data, &signature);
    OEMCrypto_KeyRefreshObject key_array[key_count];

    const uint8_t* message_ptr = reinterpret_cast<const uint8_t*>(&data);
    FillRefreshArray(data, key_array, key_count);
    OEMCryptoResult sts = OEMCrypto_RefreshKeys(session_id(), message_ptr, sizeof(data),
                                                &signature[0], signature.size(),
                                                key_count, key_array);
    if( expect_good ) {
      ASSERT_EQ(OEMCrypto_SUCCESS,sts);
    } else {
      ASSERT_NE(OEMCrypto_SUCCESS,sts);
    }

    // TODO(fredgc): make sure duration is reset.
    // Select the key (from FillSimpleMessage)
    vector<uint8_t> keyId = wvcdm::a2b_hex("000000000000000000000000");
    sts = OEMCrypto_SelectKey(session_id(), &keyId[0], keyId.size());
    ASSERT_EQ(OEMCrypto_SUCCESS, sts);

    // Set up our expected input and output
    vector<uint8_t> encryptedData = wvcdm::a2b_hex(
        "ec261c115f9d5cda1d5cc7d33c4e37362d1397c89efdd1da5f0065c4848b0462"
        "337ba14693735203c9b4184e362439c0cea5e5d1a628425eddf8a6bf9ba901ca"
        "46f5a9fd973cffbbe3c276af9919e2e8f6f3f420538b7a0d6dc41487874d96b8"
        "efaedb45a689b91beb8c20d36140ad467d9d620b19a5fc6f223b57e0e6a7f913"
        "00fd899e5e1b89963e83067ca0912aa5b79df683e2530b55a9645be341bc5f07"
        "cffc724790af635c959e2644e51ba7f23bae710eb55a1f2f4e060c3c1dd1387c"
        "74415dc880492dd1d5b9ecf3f01de48a44baeb4d3ea5cc4f8d561d0865afcabb"
        "fc14a9ab9647e6e31adabb72d792f0c9ba99dc3e9205657d28fc7771d64e6d4b");
    vector<uint8_t> encryptionIv = wvcdm::a2b_hex(
        "719dbcb253b2ec702bb8c1b1bc2f3bc6");
    vector<uint8_t> unencryptedData = wvcdm::a2b_hex(
        "19ef4361e16e6825b336e2012ad8ffc9ce176ab2256e1b98aa15b7877bd8c626"
        "fa40b2e88373457cbcf4f1b4b9793434a8ac03a708f85974cff01bddcbdd7a8e"
        "e33fd160c1d5573bfd8104efd23237edcf28205c3673920553f8dd5e916604b0"
        "1082345181dceeae5ea39d829c7f49e1850c460645de33c288723b7ae3d91a17"
        "a3f04195cd1945ba7b0f37fef7e82368be30f04365d877766f6d56f67d22a244"
        "ef2596d3053f657c1b5d90b64e11797edf1c198a23a7bfc20e4d44c74ae41280"
        "a8317f443255f4020eda850ff0954e308f53a634cbce799ae58911bc59ccd6a5"
        "de2ac53ee0fa7ea15fc692cc892acc0090865dc57becacddf362a092dfd3040b");

    // Describe the output
    uint8_t outputBuffer[256];
    OEMCrypto_DestBufferDesc destBuffer;
    destBuffer.type = OEMCrypto_BufferType_Clear;
    destBuffer.buffer.clear.address = outputBuffer;
    destBuffer.buffer.clear.max_length = sizeof(outputBuffer);
    // Decrypt the data
    sts = OEMCrypto_DecryptCTR(session_id(), &encryptedData[0],
                               encryptedData.size(), true, &encryptionIv[0], 0,
                               &destBuffer,
                               OEMCrypto_FirstSubsample | OEMCrypto_LastSubsample);
    ASSERT_EQ(OEMCrypto_SUCCESS, sts);
    ASSERT_EQ(0, memcmp(&unencryptedData[0], outputBuffer,
                        unencryptedData.size()));

    sleep(kShortSleep);  //  Should still be valid key.

    memset(outputBuffer, 0, sizeof(outputBuffer));
    destBuffer.type = OEMCrypto_BufferType_Clear;
    destBuffer.buffer.clear.address = outputBuffer;
    destBuffer.buffer.clear.max_length = sizeof(outputBuffer);

    // Decrypt the data
    sts = OEMCrypto_DecryptCTR(session_id(), &encryptedData[0],
                               encryptedData.size(), true, &encryptionIv[0], 0,
                               &destBuffer,
                               OEMCrypto_FirstSubsample | OEMCrypto_LastSubsample);
    ASSERT_EQ(OEMCrypto_SUCCESS, sts);
    ASSERT_EQ(0, memcmp(&unencryptedData[0], outputBuffer,
                        unencryptedData.size()));

    sleep(kShortSleep + kLongSleep);  // Should be after first expiration.

    memset(outputBuffer, 0, sizeof(outputBuffer));
    destBuffer.type = OEMCrypto_BufferType_Clear;
    destBuffer.buffer.clear.address = outputBuffer;
    destBuffer.buffer.clear.max_length = sizeof(outputBuffer);

    // Decrypt the data
    sts = OEMCrypto_DecryptCTR(session_id(), &encryptedData[0],
                               encryptedData.size(), true, &encryptionIv[0], 0,
                               &destBuffer,
                               OEMCrypto_FirstSubsample | OEMCrypto_LastSubsample);
    if( expect_good) {
      ASSERT_EQ(OEMCrypto_SUCCESS, sts);
      ASSERT_EQ(0, memcmp(&unencryptedData[0], outputBuffer,
                          unencryptedData.size()));
    } else {
      ASSERT_NE(OEMCrypto_SUCCESS, sts);
      ASSERT_NE(0, memcmp(&unencryptedData[0], outputBuffer,
                          unencryptedData.size()));
    }
  }

  void FillSimpleMessage(MessageData* data, uint32_t duration, uint32_t control,
                         uint32_t nonce) {
    OEMCrypto_GetRandom(data->mac_key_iv, sizeof(data->mac_key_iv));
    OEMCrypto_GetRandom(data->mac_keys, sizeof(data->mac_keys));
    for (unsigned int i = 0; i <  kNumKeys; i++) {
      memset(data->keys[i].key_id, i, kTestKeyIdLength);
      OEMCrypto_GetRandom(data->keys[i].key_data,
                          sizeof(data->keys[i].key_data));
      data->keys[i].key_data_length = wvcdm::KEY_SIZE;
      OEMCrypto_GetRandom(data->keys[i].key_iv, sizeof(data->keys[i].key_iv));
      OEMCrypto_GetRandom(data->keys[i].control_iv,
                          sizeof(data->keys[i].control_iv));
      memcpy(data->keys[i].control.verification, "kctl", 4);
      data->keys[i].control.duration     = htonl(duration);
      data->keys[i].control.nonce        = htonl(nonce);
      data->keys[i].control.control_bits = htonl(control);
    }
    // For the canned decryption content, The first key is:
    vector<uint8_t> key = wvcdm::a2b_hex("39AD33E5719656069F9EDE9EBBA7A77D");
    memcpy(data->keys[0].key_data, &key[0], key.size());
  }

  void FillRefreshMessage(MessageData* data, int key_count,
                          uint32_t control_bits, uint32_t nonce) {
    for (unsigned int i = 0; i <  kNumKeys; i++) {
      memset(data->keys[i].key_id, i, kTestKeyIdLength);
      memcpy(data->keys[i].control.verification, "kctl", 4);
      data->keys[i].control.duration     = htonl(kLongDuration);
      data->keys[i].control.nonce        = htonl(nonce);
      data->keys[i].control.control_bits = htonl(control_bits);
    }
  }

  void EncryptMessage(const MessageData& data,
                      MessageData* encrypted) {
    *encrypted = data;

    uint8_t iv_buffer[16];
    memcpy(iv_buffer, &data.mac_key_iv[0], wvcdm::KEY_IV_SIZE);
    AES_KEY aes_key;
    AES_set_encrypt_key(&enc_key_[0], 128, &aes_key);
    AES_cbc_encrypt(&data.mac_keys[0], &encrypted->mac_keys[0],
                    2*wvcdm::MAC_KEY_SIZE, &aes_key, iv_buffer, AES_ENCRYPT);

    for (unsigned int i = 0; i <  kNumKeys; i++) {
      memcpy(iv_buffer, &data.keys[i].control_iv[0], wvcdm::KEY_IV_SIZE);
      AES_set_encrypt_key(&data.keys[i].key_data[0], 128, &aes_key);
      AES_cbc_encrypt(reinterpret_cast<const uint8_t*>(&data.keys[i].control),
                      reinterpret_cast<uint8_t*>(&encrypted->keys[i].control),
                      wvcdm::KEY_SIZE, &aes_key, iv_buffer, AES_ENCRYPT);

      memcpy(iv_buffer, &data.keys[i].key_iv[0], wvcdm::KEY_IV_SIZE);
      AES_set_encrypt_key(&enc_key_[0], 128, &aes_key);
      AES_cbc_encrypt(&data.keys[i].key_data[0],
                      &encrypted->keys[i].key_data[0], data.keys[i].key_data_length,
                      &aes_key, iv_buffer, AES_ENCRYPT);
    }
  }

  void EncryptMessage(RSAPrivateKeyMessage* data,
                      RSAPrivateKeyMessage* encrypted) {
    *encrypted = *data;
    size_t padding = wvcdm::KEY_SIZE-(data->rsa_key_length % wvcdm::KEY_SIZE);
    memset(data->rsa_key + data->rsa_key_length,
           static_cast<uint8_t>(padding), padding);
    encrypted->rsa_key_length = data->rsa_key_length + padding;
    uint8_t iv_buffer[16];
    memcpy(iv_buffer, &data->rsa_key_iv[0], wvcdm::KEY_IV_SIZE);
    AES_KEY aes_key;
    AES_set_encrypt_key(&enc_key_[0], 128, &aes_key);
    AES_cbc_encrypt(&data->rsa_key[0], &encrypted->rsa_key[0],
                    encrypted->rsa_key_length, &aes_key, iv_buffer,
                    AES_ENCRYPT);
  }

  template<typename T>
  void ServerSignMessage(const T& data, std::vector<uint8_t>* signature) {
    signature->resize(SHA256_DIGEST_LENGTH);
    unsigned int md_len = SHA256_DIGEST_LENGTH;
    HMAC(EVP_sha256(), &mac_key_server_[0], SHA256_DIGEST_LENGTH,
         reinterpret_cast<const uint8_t*>(&data), sizeof(data),
         &(signature->front()), &md_len);
  }

  void ClientSignMessage(const vector<uint8_t> &data,
                         std::vector<uint8_t>* signature) {
    signature->resize(SHA256_DIGEST_LENGTH);
    unsigned int md_len = SHA256_DIGEST_LENGTH;
    HMAC(EVP_sha256(), &mac_key_client_[0], SHA256_DIGEST_LENGTH,
         &(data.front()), data.size(), &(signature->front()), &md_len);
  }

  void FillKeyArray(const MessageData& data,
                    OEMCrypto_KeyObject* key_array) {
    for (unsigned int i = 0; i <  kNumKeys; i++) {
      key_array[i].key_id = data.keys[i].key_id;
      key_array[i].key_id_length = kTestKeyIdLength;
      key_array[i].key_data_iv = data.keys[i].key_iv;
      key_array[i].key_data = data.keys[i].key_data;
      key_array[i].key_data_length = data.keys[i].key_data_length;
      key_array[i].key_control_iv = data.keys[i].control_iv;
      key_array[i].key_control
          = reinterpret_cast<const uint8_t*>(&data.keys[i].control);
    }
  }

  void FillRefreshArray(const MessageData& data,
                        OEMCrypto_KeyRefreshObject* key_array, const int key_count) {
    for (int i = 0; i < key_count; i++) {
      if( key_count > 1 ) {
        key_array[i].key_id = data.keys[i].key_id;
        key_array[i].key_id_length = kTestKeyIdLength;
      } else {
        key_array[i].key_id = NULL;
        key_array[i].key_id_length = 0;
      }
      // TODO(fredgc): Is this valid?  Is key control encrypted on renewal?
      // key_array[i].key_control_iv = data.keys[i].control_iv;
      key_array[i].key_control_iv = NULL;
      key_array[i].key_control
          = reinterpret_cast<const uint8_t*>(&data.keys[i].control);
    }
  }

  void MakeRSACertificate(struct RSAPrivateKeyMessage* encrypted,
                          std::vector<uint8_t>* signature) {
    vector<uint8_t> context = wvcdm::a2b_hex(
        "0a4c08001248000000020000101907d9ffde13aa95c122678053362136bdf840"
        "8f8276e4c2d87ec52b61aa1b9f646e58734930acebe899b3e464189a14a87202"
        "fb02574e70640bd22ef44b2d7e3912250a230a14080112100915007caa9b5931"
        "b76a3a85f046523e10011a09393837363534333231180120002a0c3138383637"
        "38373430350000");

    OEMCryptoResult sts;

    // Generate signature
    size_t gen_signature_length = 0;
    sts = OEMCrypto_GenerateSignature(session_id(), &context[0],
                                      context.size(), NULL,
                                      &gen_signature_length);
    ASSERT_EQ(OEMCrypto_ERROR_SHORT_BUFFER, sts);
    ASSERT_EQ(static_cast<size_t>(32), gen_signature_length);
    static const uint32_t SignatureBufferMaxLength = 256;
    uint8_t gen_signature[SignatureBufferMaxLength];
    sts = OEMCrypto_GenerateSignature(session_id(), &context[0],
                                      context.size(), gen_signature,
                                      &gen_signature_length);
    ASSERT_EQ(OEMCrypto_SUCCESS, sts);
    std::vector<uint8_t> expected_signature;
    ClientSignMessage(context, &expected_signature);
    ASSERT_EQ(0, memcmp(&expected_signature[0], gen_signature,
                        expected_signature.size()));

    // Rewrap Canned Response

    // In the real world, the signature above would just have been used to
    // contact the certificate provisioning server to get this response.

    struct RSAPrivateKeyMessage message;
    memcpy(message.rsa_key, kTestRSAPKCS8PrivateKeyInfo2_2048,
           sizeof(kTestRSAPKCS8PrivateKeyInfo2_2048));
    OEMCrypto_GetRandom(message.rsa_key_iv, wvcdm::KEY_IV_SIZE);
    message.rsa_key_length = sizeof(kTestRSAPKCS8PrivateKeyInfo2_2048);
    message.nonce = nonce_;

    EncryptMessage(&message, encrypted);
    ServerSignMessage(*encrypted, signature);
  }

  void RewrapRSAKey(const struct RSAPrivateKeyMessage& encrypted,
                    const std::vector<uint8_t>& signature,
                    vector<uint8_t>* wrapped_key) {
    size_t wrapped_key_length = 0;
    const uint8_t* message_ptr = reinterpret_cast<const uint8_t*>(&encrypted);
    ASSERT_EQ(OEMCrypto_ERROR_SHORT_BUFFER,
              OEMCrypto_RewrapDeviceRSAKey(session_id(), message_ptr,
                                           sizeof(encrypted), &signature[0],
                                           signature.size(), &encrypted.nonce,
                                           encrypted.rsa_key,
                                           encrypted.rsa_key_length,
                                           encrypted.rsa_key_iv, NULL,
                                           &wrapped_key_length));
    wrapped_key->clear();
    wrapped_key->resize(wrapped_key_length);
    ASSERT_EQ(OEMCrypto_SUCCESS,
              OEMCrypto_RewrapDeviceRSAKey(session_id(), message_ptr,
                                           sizeof(encrypted), &signature[0],
                                           signature.size(), &encrypted.nonce,
                                           encrypted.rsa_key,
                                           encrypted.rsa_key_length,
                                           encrypted.rsa_key_iv,
                                           &(wrapped_key->front()),
                                           &wrapped_key_length));
  }

  bool PreparePublicKey(const uint8_t key[], size_t length) {
    uint8_t const* p = key;
    public_rsa_ = d2i_RSAPublicKey(0, &p , length);
    if (!public_rsa_) {
      cout << "d2i_RSAPrivateKey failed. ";
      dump_openssl_error();
      return false;
    }
    return true;
  }

  bool VerifyRSASignature(const uint8_t* message,
                          size_t message_length,
                          uint8_t* signature,
                          size_t* signature_length) {
    if (!public_rsa_) {
      cout << "No public RSA key loaded in test code.\n";
      return false;
    }
    if (*signature_length != static_cast<size_t>(RSA_size(public_rsa_))) {
      cout << "Signature size is wrong. " << *signature_length
           << ", should be " << RSA_size(public_rsa_) << "\n";
      return false;
    }

    // Hash the message using SHA1.
    uint8_t hash[SHA_DIGEST_LENGTH];
    if (!SHA1(message, message_length, hash)) {
      cout << "Error computing SHA1. ";
      dump_openssl_error();
      return false;
    }

    // Decrypt signature to padded digest.
    uint8_t padded_digest[*signature_length];
    int status;
    status = RSA_public_decrypt(*signature_length, signature, padded_digest,
                                public_rsa_, RSA_NO_PADDING);
    if (status == -1) {
      cout << "VerifyRSASignature. in RSA_Public_digest ";
      dump_openssl_error();
      return false;
    }
    status = RSA_verify_PKCS1_PSS(public_rsa_, hash, EVP_sha1(),
                                  padded_digest, SHA_DIGEST_LENGTH);
    if (status != 1) {
      cout << "VerifyRSASignature. in RSA_verify_PKCS1_PSS ";
      dump_openssl_error();
      return false;
    }
    return true;
  }

  bool GenerateRSASessionKey(vector<uint8_t>* enc_session_key,
                             vector<uint8_t>* mac_context,
                             vector<uint8_t>* enc_context) {
    if (!public_rsa_) {
      cout << "No public RSA key loaded in test code.\n";
      return false;
    }
    vector<uint8_t> session_key = wvcdm::a2b_hex(
        "6fa479c731d2770b6a61a5d1420bb9d1");
    *mac_context = wvcdm::a2b_hex(
        "41555448454e5449434154494f4e000a4c08001248000000020000101907d9ff"
        "de13aa95c122678053362136bdf8408f8276e4c2d87ec52b61aa1b9f646e5873"
        "4930acebe899b3e464189a14a87202fb02574e70640bd22ef44b2d7e3912250a"
        "230a14080112100915007caa9b5931b76a3a85f046523e10011a093938373635"
        "34333231180120002a0c31383836373837343035000000000100");
    *enc_context = wvcdm::a2b_hex(
        "454e4352595054494f4e000a4c08001248000000020000101907d9ffde13aa95"
        "c122678053362136bdf8408f8276e4c2d87ec52b61aa1b9f646e58734930aceb"
        "e899b3e464189a14a87202fb02574e70640bd22ef44b2d7e3912250a230a1408"
        "0112100915007caa9b5931b76a3a85f046523e10011a09393837363534333231"
        "180120002a0c31383836373837343035000000000080");

    enc_session_key->assign(RSA_size(public_rsa_), 0);
    int status = RSA_public_encrypt(session_key.size(),
                                    &session_key[0],
                                    &(enc_session_key->front()),
                                    public_rsa_, RSA_PKCS1_OAEP_PADDING);
    if (status != RSA_size(public_rsa_)) {
      cout << "GenerateRSASessionKey error encrypting session key. ";
      dump_openssl_error();
      return false;
    }
    return true;
  }

  void InstallRSASessionTestKey(const vector<uint8_t>& wrapped_rsa_key) {
    ASSERT_EQ(OEMCrypto_SUCCESS,
              OEMCrypto_LoadDeviceRSAKey(session_id(), &wrapped_rsa_key[0],
                                         wrapped_rsa_key.size()));
    GenerateNonce(&nonce_);
    vector<uint8_t> enc_session_key;
    vector<uint8_t> mac_context;
    vector<uint8_t> enc_context;
    ASSERT_TRUE(PreparePublicKey(kTestRSAPublicKey2_2048,
                                 sizeof(kTestRSAPublicKey2_2048)));
    ASSERT_TRUE(GenerateRSASessionKey(&enc_session_key, &mac_context,
                                      &enc_context));

    ASSERT_EQ(OEMCrypto_SUCCESS,
              OEMCrypto_DeriveKeysFromSessionKey(
                  session_id(), &enc_session_key[0], enc_session_key.size(),
                  &mac_context[0], mac_context.size(),
                  &enc_context[0], enc_context.size()));

    mac_key_server_ = wvcdm::a2b_hex(
        "B09CB4482675123B66F7A8303D803F6042F43404ED3DE020811CFC13BCDF4C65");
    mac_key_client_ = wvcdm::a2b_hex(
        "B09CB4482675123B66F7A8303D803F6042F43404ED3DE020811CFC13BCDF4C65");
    enc_key_ = wvcdm::a2b_hex("CB477D09014D72C9B8DCE76C33EA43B3");
  }

 private:
  bool valid_;
  bool open_;
  string sname_;
  OEMCrypto_SESSION session_id_;
  OEMCryptoResult   session_status_;
  vector<uint8_t> mac_key_server_;
  vector<uint8_t> mac_key_client_;
  vector<uint8_t> enc_key_;
  uint32_t nonce_;
  RSA* public_rsa_;
};

class OEMCryptoClientTest : public ::testing::Test {
 protected:

  OEMCryptoClientTest() : alive_(false) {}

  bool init() {
    OEMCryptoResult result;
    if (!alive_) {
      result = OEMCrypto_Initialize();
      alive_ = (OEMCrypto_SUCCESS == result);
    }
    return alive_;
  }

  bool terminate() {
    OEMCryptoResult result;
    result = OEMCrypto_Terminate();
    if (OEMCrypto_SUCCESS == result) {
      alive_ = false;
    }
    return !alive_;
  }

  void testSetUp() {  // TODO(fredgc): Wha...
    // All these tests should be using Setup() and Teardown() so that you
    // don't need to call them manually...
    // https://code.google.com/p/googletest/wiki/Primer#Test_Fixtures:
    //                 _Using_the_Same_Data_Configuration_for_Multiple_Te
    init();
  }

  void CreateWrappedRSAKey(vector<uint8_t>* wrapped_key) {
    Session& s = createSession("RSA_Session");
    s.open();
    s.GenerateDerivedKeys();
    struct RSAPrivateKeyMessage encrypted;
    std::vector<uint8_t> signature;
    s.MakeRSACertificate(&encrypted, &signature);
    s.RewrapRSAKey(encrypted, signature, wrapped_key);
    s.close();
  }

  void testTearDown() {
    destroySessions();
    terminate();
  }

  void validateKeybox() {
    ASSERT_EQ(OEMCrypto_SUCCESS, OEMCrypto_IsKeyboxValid());
  }

  static Session badSession;

  Session& findSession(string sname) {
    map<string, Session>::iterator it = _sessions.find(sname);
    if (it != _sessions.end()) {
      return it->second;
    }
    return badSession;
  }

  Session& createSession(string sname) {
    Session temp(sname);
    _sessions.insert(pair<string, Session>(sname, temp));
    return findSession(sname);
  }

  bool destroySession(string sname) {
    Session& temp = findSession(sname);
    if (!temp.isValid()) {
      return false;
    }
    _sessions.erase(sname);
    return true;
  }

  bool destroySessions() {
    _sessions.clear();
    return true;
  }

  const uint8_t* find(const vector<uint8_t>& message,
                      const vector<uint8_t>& substring) {
    vector<uint8_t>::const_iterator pos = search(message.begin(), message.end(),
                                                 substring.begin(), substring.end());
    if (pos == message.end()) {
      return NULL;
    }
    return &(*pos);
  }

 private:
  bool alive_;
  map<string, Session> _sessions;
};

Session OEMCryptoClientTest::badSession;

///////////////////////////////////////////////////
// Keybox Tests
///////////////////////////////////////////////////

// These two tests are first, becuase it might give an idea why other
// tests are failing when the device has the wrong keybox installed.
TEST_F(OEMCryptoClientTest, VersionNumber) {
  testSetUp();

  const char* level = OEMCrypto_SecurityLevel();
  ASSERT_NE((char *)NULL, level);
  ASSERT_EQ('L', level[0]);
  cout << "             OEMCrypto Security Level is "<< level << endl;
  uint32_t version = OEMCrypto_APIVersion();
  cout << "             OEMCrypto API version is " << version << endl;
  ASSERT_EQ(oec_latest_version, version);

  testTearDown();
}

TEST_F(OEMCryptoClientTest, NormalGetKeyData) {
  testSetUp();

  OEMCryptoResult sts;
  uint8_t key_data[256];
  size_t key_data_len = sizeof(key_data);
  sts = OEMCrypto_GetKeyData(key_data, &key_data_len);

  uint32_t* data = reinterpret_cast<uint32_t*>(key_data);
  printf("             NormalGetKeyData: system_id = %d = 0x%04X, version=%d\n",
         htonl(data[1]),  htonl(data[1]), htonl(data[0]));
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);

  uint32_t system_id = htonl(data[1]);
  if (system_id == 0x1019) {
    cout << "======================================================================\n"
         << "If you run this as \"oemcrypto_test --gtest_also_run_disabled_tests\",\n"
         << "then a test keybox will be installed, and all tests will be run.      \n"
         << "======================================================================\n";
  }
  testTearDown();
}

TEST_F(OEMCryptoClientTest, KeyboxValid) {
  bool success;
  success = init();
  EXPECT_TRUE(success);
  validateKeybox();
  ASSERT_TRUE(success);
  success = terminate();
  ASSERT_TRUE(success);
}

TEST_F(OEMCryptoClientTest, NormalGetDeviceId) {
  testSetUp();

  OEMCryptoResult sts;
  uint8_t dev_id[128] = {0};
  size_t dev_id_len = 128;
  sts = OEMCrypto_GetDeviceID(dev_id, &dev_id_len);
  cout << "             NormalGetDeviceId: dev_id = " << dev_id
       << " len = " << dev_id_len << endl;
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);

  testTearDown();
}

TEST_F(OEMCryptoClientTest, GetDeviceIdShortBuffer) {
  testSetUp();

  OEMCryptoResult sts;
  uint8_t dev_id[128];
  uint32_t req_len = 11;
  for (int i = 0; i < 128; ++i) {
    dev_id[i] = 0x55;
  }
  dev_id[127] = '\0';
  size_t dev_id_len = req_len;
  sts = OEMCrypto_GetDeviceID(dev_id, &dev_id_len);
  // cout << "GetDeviceIdShortBuffer: sts = " << (int)sts << " request = "
  //      << req_len << " required = " << dev_id_len << endl;

  ASSERT_EQ(OEMCrypto_ERROR_SHORT_BUFFER, sts);

  // On short buffer error, function should return minimum buffer length
  ASSERT_TRUE(dev_id_len > req_len);

  // cout << "NormalGetDeviceId: dev_id = " << dev_id
  //      << " len = " << dev_id_len << endl;

  testTearDown();
}

///////////////////////////////////////////////////
// initialization tests
///////////////////////////////////////////////////

TEST_F(OEMCryptoClientTest, NormalInitTermination) {
  bool success;
  success = init();
  EXPECT_TRUE(success);
  success = terminate();
  ASSERT_TRUE(success);
}

///////////////////////////////////////////////////
// Session Tests
///////////////////////////////////////////////////

TEST_F(OEMCryptoClientTest, NormalSessionOpenClose) {
  Session& s = createSession("ONE");
  testSetUp();

  s.open();
  ASSERT_TRUE(s.successStatus());
  ASSERT_TRUE(s.isOpen());

  s.close();
  ASSERT_TRUE(s.successStatus());
  ASSERT_FALSE(s.isOpen());

  testTearDown();
}

TEST_F(OEMCryptoClientTest, TwoSessionsOpenClose) {
  Session& s1 = createSession("ONE");
  Session& s2 = createSession("TWO");
  testSetUp();

  s1.open();
  ASSERT_TRUE(s1.successStatus());
  ASSERT_TRUE(s1.isOpen());

  s2.open();
  ASSERT_TRUE(s2.successStatus());
  ASSERT_TRUE(s2.isOpen());

  s1.close();
  ASSERT_TRUE(s1.successStatus());
  ASSERT_FALSE(s1.isOpen());

  s2.close();
  ASSERT_TRUE(s2.successStatus());
  ASSERT_FALSE(s2.isOpen());

  testTearDown();
}

TEST_F(OEMCryptoClientTest, EightSessionsOpenClose) {
  Session& s1 = createSession("ONE");
  Session& s2 = createSession("TWO");
  Session& s3 = createSession("THREE");
  Session& s4 = createSession("FOUR");
  Session& s5 = createSession("FIVE");
  Session& s6 = createSession("SIX");
  Session& s7 = createSession("SEVEN");
  Session& s8 = createSession("EIGHT");
  testSetUp();

  s1.open();
  ASSERT_TRUE(s1.successStatus());
  ASSERT_TRUE(s1.isOpen());

  s2.open();
  ASSERT_TRUE(s2.successStatus());
  ASSERT_TRUE(s2.isOpen());

  s3.open();
  ASSERT_TRUE(s3.successStatus());
  ASSERT_TRUE(s3.isOpen());

  s4.open();
  ASSERT_TRUE(s4.successStatus());
  ASSERT_TRUE(s4.isOpen());

  s5.open();
  ASSERT_TRUE(s5.successStatus());
  ASSERT_TRUE(s5.isOpen());

  s6.open();
  ASSERT_TRUE(s6.successStatus());
  ASSERT_TRUE(s6.isOpen());

  s7.open();
  ASSERT_TRUE(s7.successStatus());
  ASSERT_TRUE(s7.isOpen());

  s8.open();
  ASSERT_TRUE(s8.successStatus());
  ASSERT_TRUE(s8.isOpen());

  s1.close();
  ASSERT_TRUE(s1.successStatus());
  ASSERT_FALSE(s1.isOpen());

  s8.close();
  ASSERT_TRUE(s8.successStatus());
  ASSERT_FALSE(s8.isOpen());

  s3.close();
  ASSERT_TRUE(s3.successStatus());
  ASSERT_FALSE(s3.isOpen());

  s6.close();
  ASSERT_TRUE(s6.successStatus());
  ASSERT_FALSE(s6.isOpen());

  s5.close();
  ASSERT_TRUE(s5.successStatus());
  ASSERT_FALSE(s5.isOpen());

  s4.close();
  ASSERT_TRUE(s4.successStatus());
  ASSERT_FALSE(s4.isOpen());

  s7.close();
  ASSERT_TRUE(s7.successStatus());
  ASSERT_FALSE(s7.isOpen());

  s2.close();
  ASSERT_TRUE(s2.successStatus());
  ASSERT_FALSE(s2.isOpen());

  testTearDown();
}

TEST_F(OEMCryptoClientTest, GenerateNonce) {
  Session& s = createSession("ONE");
  testSetUp();
  s.open();
  uint32_t nonce;

  s.GenerateNonce(&nonce);
  s.close();
  ASSERT_TRUE(s.successStatus());
  ASSERT_FALSE(s.isOpen());
  testTearDown();
}

TEST_F(OEMCryptoClientTest, GenerateTwoNonces) {
  Session& s = createSession("ONE");
  testSetUp();
  s.open();
  uint32_t nonce1;
  uint32_t nonce2;

  s.GenerateNonce(&nonce1);
  s.GenerateNonce(&nonce2);
  ASSERT_TRUE(nonce1 != nonce2);

  s.close();
  ASSERT_TRUE(s.successStatus());
  ASSERT_FALSE(s.isOpen());
  testTearDown();
}

TEST_F(OEMCryptoClientTest, GenerateDerivedKeys) {
  Session& s = createSession("ONE");
  testSetUp();
  s.open();

  s.GenerateDerivedKeys();

  s.close();
  ASSERT_TRUE(s.successStatus());
  ASSERT_FALSE(s.isOpen());
  testTearDown();
}

///////////////////////////////////////////////////
// AddKey Tests
///////////////////////////////////////////////////

/* These tests will install a test keybox.  Since this may be a problem
   on a production device, they are disabled by default.
   Run this program with the command line argument "--gtest_also_run_disabled_tests"
   to enable all of these tests.
*/

class DISABLED_TestKeybox : public OEMCryptoClientTest {
 protected:

  void InstallKeybox(const wvoec_mock::WidevineKeybox& keybox, bool good) {
    OEMCryptoResult sts;
    uint8_t wrapped[sizeof(wvoec_mock::WidevineKeybox)];
    size_t length = sizeof(wvoec_mock::WidevineKeybox);
    sts = OEMCrypto_WrapKeybox(reinterpret_cast<const uint8_t*>(&keybox),
                               sizeof(keybox),
                               wrapped,
                               &length,
                               NULL, 0);
    ASSERT_EQ(OEMCrypto_SUCCESS, sts);
    sts = OEMCrypto_InstallKeybox(wrapped, sizeof(keybox));
    if( good ) {
      ASSERT_EQ(OEMCrypto_SUCCESS, sts);
    } else {
      // Can return error now, or return error on IsKeyboxValid.
    }
  }
};

TEST_F(DISABLED_TestKeybox, CheckSystemID) {
  testSetUp();

  OEMCryptoResult sts;
  uint8_t key_data[256];
  size_t key_data_len = sizeof(key_data);
  sts = OEMCrypto_GetKeyData(key_data, &key_data_len);
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);

  uint32_t* data = reinterpret_cast<uint32_t*>(key_data);
  uint32_t system_id = htonl(data[1]);
  if (system_id != 0x1019) {

    cout << "================================================================\n"
         << "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"
         << "WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING \n"
         << "You have enabled the keybox tests.  This code WILL INSTALL A \n"
         << "TEST KEYBOX.  IT WILL REPLACE THE EXISTING KEYBOX, and you will.\n"
         << "NOT have access to production content.  Your current keybox has \n"
         << "system id " << system_id << ".\n"
         << "\n"
         << "Continue? [y/N]:\n";
    int answer = getchar();
    if (tolower(answer) != 'y') {
      cout << "Quitting tests.  whew, that was close.\n";
      exit(1);
    }
  }
  testTearDown();
}


TEST_F(DISABLED_TestKeybox, GoodKeybox) {
  testSetUp();
  wvoec_mock::WidevineKeybox keybox = kValidKeybox02;
  OEMCryptoResult sts;
  InstallKeybox(keybox, true);
  sts = OEMCrypto_IsKeyboxValid();
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);

  keybox = kValidKeybox03;
  InstallKeybox(keybox, true);
  sts = OEMCrypto_IsKeyboxValid();
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);
}

TEST_F(DISABLED_TestKeybox, DefaultKeybox) {
  testSetUp();
  ASSERT_EQ(OEMCrypto_SUCCESS, OEMCrypto_Initialize())
      << "OEMCrypto_Initialize failed.";
  OEMCryptoResult sts;
  sts = OEMCrypto_IsKeyboxValid();
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);
}

TEST_F(DISABLED_TestKeybox, BadCRCKeybox) {
  testSetUp();
  wvoec_mock::WidevineKeybox keybox = kValidKeybox02;
  keybox.crc_[1] ^= 42;
  OEMCryptoResult sts;
  InstallKeybox(keybox, false);
  sts = OEMCrypto_IsKeyboxValid();
  ASSERT_EQ(OEMCrypto_ERROR_BAD_CRC, sts);
}

TEST_F(DISABLED_TestKeybox, BadMagicKeybox) {
  testSetUp();
  wvoec_mock::WidevineKeybox keybox = kValidKeybox02;
  keybox.magic_[1] ^= 42;
  OEMCryptoResult sts;
  InstallKeybox(keybox, false);
  sts = OEMCrypto_IsKeyboxValid();
  ASSERT_EQ(OEMCrypto_ERROR_BAD_MAGIC, sts);
}

TEST_F(DISABLED_TestKeybox, BadDataKeybox) {
  testSetUp();
  wvoec_mock::WidevineKeybox keybox = kValidKeybox02;
  keybox.data_[1] ^= 42;
  OEMCryptoResult sts;
  InstallKeybox(keybox, false);
  sts = OEMCrypto_IsKeyboxValid();
  ASSERT_EQ(OEMCrypto_ERROR_BAD_CRC, sts);
}

TEST_F(DISABLED_TestKeybox, GenerateSignature) {
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();

  s.GenerateDerivedKeys();

  vector<uint8_t> context = wvcdm::a2b_hex(
      "0a4c08001248000000020000101907d9ffde13aa95c122678053362136bdf840"
      "8f8276e4c2d87ec52b61aa1b9f646e58734930acebe899b3e464189a14a87202"
      "fb02574e70640bd22ef44b2d7e3912250a230a14080112100915007caa9b5931"
      "b76a3a85f046523e10011a09393837363534333231180120002a0c3138383637"
      "38373430350000");

  static const uint32_t SignatureBufferMaxLength = 256;
  uint8_t signature[SignatureBufferMaxLength];
  size_t signature_length = SignatureBufferMaxLength;

  OEMCryptoResult sts;
  sts = OEMCrypto_GenerateSignature(
          s.session_id(),
          &context[0], context.size(), signature, &signature_length);

  ASSERT_EQ(OEMCrypto_SUCCESS, sts);

  static const uint32_t SignatureExpectedLength = 32;
  ASSERT_EQ(signature_length, SignatureExpectedLength);

  std::vector<uint8_t> expected_signature;
  s.ClientSignMessage(context, &expected_signature);
  ASSERT_EQ(0, memcmp(&expected_signature[0], signature,
                      expected_signature.size()));

  s.close();
  ASSERT_TRUE(s.successStatus());
  ASSERT_FALSE(s.isOpen());
  testTearDown();
}

TEST_F(DISABLED_TestKeybox, LoadKeyNoNonce) {
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();
  s.GenerateDerivedKeys();
  s.LoadTestKeys(kDuration, 0, 42);
  s.close();
  testTearDown();
}

TEST_F(DISABLED_TestKeybox, LoadKeyWithNonce) {
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();

  s.GenerateDerivedKeys();
  s.LoadTestKeys(0, wvoec_mock::kControlNonceEnabled, s.get_nonce());
  s.close();
  testTearDown();
}

TEST_F(DISABLED_TestKeybox, LoadKeyWithNoMAC) {
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();

  s.GenerateDerivedKeys();

  MessageData data;
  s.FillSimpleMessage(&data, 0, 0, 0);

  MessageData encrypted;
  s.EncryptMessage(data, &encrypted);
  std::vector<uint8_t> signature;
  s.ServerSignMessage(encrypted, &signature);
  OEMCrypto_KeyObject key_array[kNumKeys];
  const uint8_t* message_ptr = reinterpret_cast<const uint8_t*>(&encrypted);
  s.FillKeyArray(encrypted, key_array);
  OEMCryptoResult sts = OEMCrypto_LoadKeys(s.session_id(),
                                           message_ptr, sizeof(encrypted),
                                           &signature[0], signature.size(),
                                           NULL, NULL,
                                           kNumKeys, key_array);
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);
  s.close();
  testTearDown();
}

/* The Bad Range tests verify that OEMCrypto_LoadKeys checks the range
   of all the pointers.  It should reject a message if the pointer does
   not point into the message buffer */
TEST_F(DISABLED_TestKeybox, LoadKeyWithBadRange1) {
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();

  s.GenerateDerivedKeys();
  MessageData data;
  s.FillSimpleMessage(&data, 0, 0, 0);

  MessageData encrypted;
  s.EncryptMessage(data, &encrypted);
  std::vector<uint8_t> signature;
  s.ServerSignMessage(encrypted, &signature);
  OEMCrypto_KeyObject key_array[kNumKeys];
  const uint8_t* message_ptr = reinterpret_cast<const uint8_t*>(&encrypted);
  s.FillKeyArray(encrypted, key_array);

  vector<uint8_t> mac_keys(encrypted.mac_keys,
                           encrypted.mac_keys+sizeof(encrypted.mac_keys));

  OEMCryptoResult sts = OEMCrypto_LoadKeys(s.session_id(),
                                           message_ptr, sizeof(encrypted),
                                           &signature[0], signature.size(),
                                           encrypted.mac_key_iv,
                                           &mac_keys[0],  // Not pointing into buffer.
                                           kNumKeys, key_array);
  ASSERT_NE(OEMCrypto_SUCCESS, sts);
  s.close();
  testTearDown();
}

TEST_F(DISABLED_TestKeybox, LoadKeyWithBadRange2) {
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();

  s.GenerateDerivedKeys();
  MessageData data;
  s.FillSimpleMessage(&data, 0, 0, 0);

  MessageData encrypted;
  s.EncryptMessage(data, &encrypted);
  std::vector<uint8_t> signature;
  s.ServerSignMessage(encrypted, &signature);
  OEMCrypto_KeyObject key_array[kNumKeys];
  const uint8_t* message_ptr = reinterpret_cast<const uint8_t*>(&encrypted);
  s.FillKeyArray(encrypted, key_array);

  vector<uint8_t> mac_key_iv(encrypted.mac_key_iv,
                          encrypted.mac_key_iv+sizeof(encrypted.mac_key_iv));

  OEMCryptoResult sts = OEMCrypto_LoadKeys(s.session_id(),
                                           message_ptr, sizeof(encrypted),
                                           &signature[0], signature.size(),
                                           &mac_key_iv[0],  // bad.
                                           encrypted.mac_keys,
                                           kNumKeys, key_array);
  ASSERT_NE(OEMCrypto_SUCCESS, sts);
  s.close();
  testTearDown();
}

TEST_F(DISABLED_TestKeybox, LoadKeyWithBadRange3) {
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();

  s.GenerateDerivedKeys();

  MessageData data;
  s.FillSimpleMessage(&data, 0, 0, 0);

  MessageData encrypted;
  s.EncryptMessage(data, &encrypted);
  std::vector<uint8_t> signature;
  s.ServerSignMessage(encrypted, &signature);
  OEMCrypto_KeyObject key_array[kNumKeys];
  const uint8_t* message_ptr = reinterpret_cast<const uint8_t*>(&encrypted);
  s.FillKeyArray(encrypted, key_array);

  vector<uint8_t> bad_buffer(encrypted.keys[0].key_id,
                             encrypted.keys[0].key_id+kTestKeyIdLength);
  key_array[0].key_id = &bad_buffer[0];

  OEMCryptoResult sts = OEMCrypto_LoadKeys(s.session_id(),
                                           message_ptr, sizeof(encrypted),
                                           &signature[0], signature.size(),
                                           encrypted.mac_key_iv,
                                           encrypted.mac_keys,
                                           kNumKeys, key_array);
  ASSERT_NE(OEMCrypto_SUCCESS, sts);
  s.close();
  testTearDown();
}

TEST_F(DISABLED_TestKeybox, LoadKeyWithBadRange4) {
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();

  s.GenerateDerivedKeys();

  MessageData data;
  s.FillSimpleMessage(&data, 0, 0, 0);

  MessageData encrypted;
  s.EncryptMessage(data, &encrypted);
  std::vector<uint8_t> signature;
  s.ServerSignMessage(encrypted, &signature);
  OEMCrypto_KeyObject key_array[kNumKeys];
  const uint8_t* message_ptr = reinterpret_cast<const uint8_t*>(&encrypted);
  s.FillKeyArray(encrypted, key_array);

  vector<uint8_t> bad_buffer(encrypted.keys[1].key_data,
                             encrypted.keys[1].key_data+wvcdm::KEY_SIZE);
  key_array[1].key_data = &bad_buffer[0];

  OEMCryptoResult sts = OEMCrypto_LoadKeys(s.session_id(),
                                           message_ptr, sizeof(encrypted),
                                           &signature[0], signature.size(),
                                           encrypted.mac_key_iv,
                                           encrypted.mac_keys,
                                           kNumKeys, key_array);
  ASSERT_NE(OEMCrypto_SUCCESS, sts);
  s.close();
  testTearDown();
}

TEST_F(DISABLED_TestKeybox, LoadKeyWithBadRange5) {
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();

  s.GenerateDerivedKeys();

  MessageData data;
  s.FillSimpleMessage(&data, 0, 0, 0);

  MessageData encrypted;
  s.EncryptMessage(data, &encrypted);
  std::vector<uint8_t> signature;
  s.ServerSignMessage(encrypted, &signature);
  OEMCrypto_KeyObject key_array[kNumKeys];
  const uint8_t* message_ptr = reinterpret_cast<const uint8_t*>(&encrypted);
  s.FillKeyArray(encrypted, key_array);

  vector<uint8_t> bad_buffer(encrypted.keys[1].key_iv,
                             encrypted.keys[1].key_iv+sizeof(encrypted.keys[1].key_iv));
  key_array[1].key_data_iv = &bad_buffer[0];

  OEMCryptoResult sts = OEMCrypto_LoadKeys(s.session_id(),
                                           message_ptr, sizeof(encrypted),
                                           &signature[0], signature.size(),
                                           encrypted.mac_key_iv,
                                           encrypted.mac_keys,
                                           kNumKeys, key_array);
  ASSERT_NE(OEMCrypto_SUCCESS, sts);
  s.close();
  testTearDown();
}

TEST_F(DISABLED_TestKeybox, LoadKeyWithBadRange6) {
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();

  s.GenerateDerivedKeys();

  MessageData data;
  s.FillSimpleMessage(&data, 0, 0, 0);

  MessageData encrypted;
  s.EncryptMessage(data, &encrypted);
  std::vector<uint8_t> signature;
  s.ServerSignMessage(encrypted, &signature);
  OEMCrypto_KeyObject key_array[kNumKeys];
  const uint8_t* message_ptr = reinterpret_cast<const uint8_t*>(&encrypted);
  s.FillKeyArray(encrypted, key_array);

  vector<uint8_t> bad_buffer(key_array[2].key_control,
                             key_array[2].key_control+sizeof(encrypted.keys[1].control));
  key_array[2].key_control = &bad_buffer[0];

  OEMCryptoResult sts = OEMCrypto_LoadKeys(s.session_id(),
                                           message_ptr, sizeof(encrypted),
                                           &signature[0], signature.size(),
                                           encrypted.mac_key_iv,
                                           encrypted.mac_keys,
                                           kNumKeys, key_array);
  ASSERT_NE(OEMCrypto_SUCCESS, sts);
  s.close();
  testTearDown();
}

TEST_F(DISABLED_TestKeybox, LoadKeyWithBadRange7) {
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();

  s.GenerateDerivedKeys();

  MessageData data;
  s.FillSimpleMessage(&data, 0, 0, 0);

  MessageData encrypted;
  s.EncryptMessage(data, &encrypted);
  std::vector<uint8_t> signature;
  s.ServerSignMessage(encrypted, &signature);
  OEMCrypto_KeyObject key_array[kNumKeys];
  const uint8_t* message_ptr = reinterpret_cast<const uint8_t*>(&encrypted);
  s.FillKeyArray(encrypted, key_array);

  vector<uint8_t> bad_buffer(key_array[2].key_control_iv,
                             key_array[2].key_control_iv+sizeof(encrypted.keys[1].control_iv));
  key_array[2].key_control_iv = &bad_buffer[0];

  OEMCryptoResult sts = OEMCrypto_LoadKeys(s.session_id(),
                                           message_ptr, sizeof(encrypted),
                                           &signature[0], signature.size(),
                                           encrypted.mac_key_iv,
                                           encrypted.mac_keys,
                                           kNumKeys, key_array);
  ASSERT_NE(OEMCrypto_SUCCESS, sts);
  s.close();
  testTearDown();
}

TEST_F(DISABLED_TestKeybox, LoadKeyWithBadNonce) {
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();

  s.GenerateDerivedKeys();

  MessageData data;
  s.FillSimpleMessage(&data, 0, wvoec_mock::kControlNonceEnabled,
                      42);  // bad nonce.
  MessageData encrypted;
  s.EncryptMessage(data, &encrypted);
  std::vector<uint8_t> signature;
  s.ServerSignMessage(encrypted, &signature);
  OEMCrypto_KeyObject key_array[kNumKeys];
  const uint8_t* message_ptr = reinterpret_cast<const uint8_t*>(&encrypted);
  s.FillKeyArray(encrypted, key_array);

  OEMCryptoResult sts = OEMCrypto_LoadKeys(
                          s.session_id(),
                          message_ptr, sizeof(encrypted),
                          &signature[0], signature.size(),
                          encrypted.mac_key_iv,
                          encrypted.mac_keys,
                          kNumKeys, key_array);

  ASSERT_NE(OEMCrypto_SUCCESS, sts);

  s.close();
  testTearDown();
}

TEST_F(DISABLED_TestKeybox, LoadKeyWithBadVerification) {
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();

  s.GenerateDerivedKeys();

  MessageData data;
  s.FillSimpleMessage(&data, 0, 0, 0);
  data.keys[1].control.verification[2] = 'Z';

  MessageData encrypted;
  s.EncryptMessage(data, &encrypted);
  std::vector<uint8_t> signature;
  s.ServerSignMessage(encrypted, &signature);
  OEMCrypto_KeyObject key_array[kNumKeys];
  const uint8_t* message_ptr = reinterpret_cast<const uint8_t*>(&encrypted);
  s.FillKeyArray(encrypted, key_array);

  OEMCryptoResult sts = OEMCrypto_LoadKeys(
                          s.session_id(),
                          message_ptr, sizeof(encrypted),
                          &signature[0], signature.size(),
                          encrypted.mac_key_iv,
                          encrypted.mac_keys,
                          kNumKeys, key_array);

  ASSERT_NE(OEMCrypto_SUCCESS, sts);

  s.close();
  testTearDown();
}

TEST_F(DISABLED_TestKeybox, LoadKeysBadSignature) {
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();

  s.GenerateDerivedKeys();

  MessageData data;
  s.FillSimpleMessage(&data, 0, 0, 0);

  MessageData encrypted;
  s.EncryptMessage(data, &encrypted);
  std::vector<uint8_t> signature;
  s.ServerSignMessage(encrypted, &signature);
  OEMCrypto_KeyObject key_array[kNumKeys];
  const uint8_t* message_ptr = reinterpret_cast<const uint8_t*>(&encrypted);
  s.FillKeyArray(encrypted, key_array);

  signature[0] ^= 42;  // Bad signature.

  OEMCryptoResult sts = OEMCrypto_LoadKeys(
                          s.session_id(),
                          message_ptr, sizeof(encrypted),
                          &signature[0], signature.size(),
                          encrypted.mac_key_iv,
                          encrypted.mac_keys,
                          kNumKeys, key_array);

  ASSERT_NE(OEMCrypto_SUCCESS, sts);

  s.close();
  testTearDown();
}

TEST_F(DISABLED_TestKeybox, LoadKeysWithNoDerivedKeys) {
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();

  // s.GenerateDerivedKeys();

  MessageData data;
  s.FillSimpleMessage(&data, 0, 0, 0);

  MessageData encrypted;
  s.EncryptMessage(data, &encrypted);
  std::vector<uint8_t> signature;
  s.ServerSignMessage(encrypted, &signature);
  OEMCrypto_KeyObject key_array[kNumKeys];
  const uint8_t* message_ptr = reinterpret_cast<const uint8_t*>(&encrypted);
  s.FillKeyArray(encrypted, key_array);

  OEMCryptoResult sts = OEMCrypto_LoadKeys(
                          s.session_id(),
                          message_ptr, sizeof(encrypted),
                          &signature[0], signature.size(),
                          encrypted.mac_key_iv,
                          encrypted.mac_keys,
                          kNumKeys, key_array);

  ASSERT_NE(OEMCrypto_SUCCESS, sts);

  s.close();
  testTearDown();
}

///////////////////////////////////////////////////
// Load, Refresh Keys Test
///////////////////////////////////////////////////

class DISABLED_RefreshKeyTest : public DISABLED_TestKeybox {
 public:
  void RefreshWithNonce(const int key_count) {
    Session& s = createSession("ONE");
    s.open();
    s.GenerateDerivedKeys();
    s.LoadTestKeys(kDuration, wvoec_mock::kControlNonceEnabled, s.get_nonce());
    uint32_t nonce;
    s.GenerateNonce(&nonce);
    s.RefreshTestKeys(key_count, wvoec_mock::kControlNonceEnabled, nonce, true);
    s.close();
  }

  void RefresNoNonce(const int key_count) {
    Session& s = createSession("ONE");
    s.open();
    s.GenerateDerivedKeys();
    s.LoadTestKeys(kDuration, 0, 0);
    uint32_t nonce;
    s.GenerateNonce(&nonce);
    s.RefreshTestKeys(key_count,0, 0, true);
    s.close();
  }

  void RefreshOldNonce(const int key_count) {
    Session& s = createSession("ONE");
    s.open();
    s.GenerateDerivedKeys();
    s.LoadTestKeys(kDuration, wvoec_mock::kControlNonceEnabled, s.get_nonce());
    uint32_t nonce = s.get_nonce();
    s.RefreshTestKeys(key_count, wvoec_mock::kControlNonceEnabled, nonce,
                      false);
    s.close();
  }
  void RefreshBadNonce(const int key_count) {
    Session& s = createSession("ONE");
    s.open();
    s.GenerateDerivedKeys();
    s.LoadTestKeys(kDuration, wvoec_mock::kControlNonceEnabled, s.get_nonce());
    uint32_t nonce;
    s.GenerateNonce(&nonce);
    nonce ^= 42;
    s.RefreshTestKeys(key_count, wvoec_mock::kControlNonceEnabled, nonce,
                      false);
    s.close();
  }

};

TEST_F(DISABLED_RefreshKeyTest, RefreshAllKeys) {
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  RefreshWithNonce(1);  // One key control block to refresh all keys.
  RefreshOldNonce(1);
  RefreshBadNonce(1);
  testTearDown();
}

TEST_F(DISABLED_RefreshKeyTest, RefreshEachKeys) {
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  RefreshWithNonce(kNumKeys);  // Each key control block updates a different key.
  RefreshOldNonce(kNumKeys);
  RefreshBadNonce(kNumKeys);
  testTearDown();
}

///////////////////////////////////////////////////
// Decrypt Tests
///////////////////////////////////////////////////

TEST_F(DISABLED_TestKeybox, Decrypt) {
  OEMCryptoResult sts;
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();

  s.GenerateDerivedKeys();
  s.LoadTestKeys(kDuration, 0, 0);

  // Select the key (from FillSimpleMessage)
  vector<uint8_t> keyId = wvcdm::a2b_hex("000000000000000000000000");
  sts = OEMCrypto_SelectKey(s.session_id(), &keyId[0], keyId.size());
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);

  // Set up our expected input and output
  vector<uint8_t> encryptedData = wvcdm::a2b_hex(
      "ec261c115f9d5cda1d5cc7d33c4e37362d1397c89efdd1da5f0065c4848b0462"
      "337ba14693735203c9b4184e362439c0cea5e5d1a628425eddf8a6bf9ba901ca"
      "46f5a9fd973cffbbe3c276af9919e2e8f6f3f420538b7a0d6dc41487874d96b8"
      "efaedb45a689b91beb8c20d36140ad467d9d620b19a5fc6f223b57e0e6a7f913"
      "00fd899e5e1b89963e83067ca0912aa5b79df683e2530b55a9645be341bc5f07"
      "cffc724790af635c959e2644e51ba7f23bae710eb55a1f2f4e060c3c1dd1387c"
      "74415dc880492dd1d5b9ecf3f01de48a44baeb4d3ea5cc4f8d561d0865afcabb"
      "fc14a9ab9647e6e31adabb72d792f0c9ba99dc3e9205657d28fc7771d64e6d4b");
  vector<uint8_t> encryptionIv = wvcdm::a2b_hex(
      "719dbcb253b2ec702bb8c1b1bc2f3bc6");
  vector<uint8_t> unencryptedData = wvcdm::a2b_hex(
      "19ef4361e16e6825b336e2012ad8ffc9ce176ab2256e1b98aa15b7877bd8c626"
      "fa40b2e88373457cbcf4f1b4b9793434a8ac03a708f85974cff01bddcbdd7a8e"
      "e33fd160c1d5573bfd8104efd23237edcf28205c3673920553f8dd5e916604b0"
      "1082345181dceeae5ea39d829c7f49e1850c460645de33c288723b7ae3d91a17"
      "a3f04195cd1945ba7b0f37fef7e82368be30f04365d877766f6d56f67d22a244"
      "ef2596d3053f657c1b5d90b64e11797edf1c198a23a7bfc20e4d44c74ae41280"
      "a8317f443255f4020eda850ff0954e308f53a634cbce799ae58911bc59ccd6a5"
      "de2ac53ee0fa7ea15fc692cc892acc0090865dc57becacddf362a092dfd3040b");

  // Describe the output
  uint8_t outputBuffer[256];
  OEMCrypto_DestBufferDesc destBuffer;
  destBuffer.type = OEMCrypto_BufferType_Clear;
  destBuffer.buffer.clear.address = outputBuffer;
  destBuffer.buffer.clear.max_length = sizeof(outputBuffer);

  // Decrypt the data
  sts = OEMCrypto_DecryptCTR(s.session_id(), &encryptedData[0],
                             encryptedData.size(), true, &encryptionIv[0], 0,
                             &destBuffer,
                             OEMCrypto_FirstSubsample | OEMCrypto_LastSubsample);
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);
  ASSERT_EQ(0, memcmp(&unencryptedData[0], outputBuffer,
                      unencryptedData.size()));

  s.close();
  testTearDown();
}

TEST_F(DISABLED_TestKeybox, DecryptZeroDuration) {
  OEMCryptoResult sts;
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();

  s.GenerateDerivedKeys();
  s.LoadTestKeys(0, 0, 0);

  // Select the key (from FillSimpleMessage)
  vector<uint8_t> keyId = wvcdm::a2b_hex("000000000000000000000000");
  sts = OEMCrypto_SelectKey(s.session_id(), &keyId[0], keyId.size());
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);

  // Set up our expected input and output
  vector<uint8_t> encryptedData = wvcdm::a2b_hex(
      "ec261c115f9d5cda1d5cc7d33c4e37362d1397c89efdd1da5f0065c4848b0462"
      "337ba14693735203c9b4184e362439c0cea5e5d1a628425eddf8a6bf9ba901ca"
      "46f5a9fd973cffbbe3c276af9919e2e8f6f3f420538b7a0d6dc41487874d96b8"
      "efaedb45a689b91beb8c20d36140ad467d9d620b19a5fc6f223b57e0e6a7f913"
      "00fd899e5e1b89963e83067ca0912aa5b79df683e2530b55a9645be341bc5f07"
      "cffc724790af635c959e2644e51ba7f23bae710eb55a1f2f4e060c3c1dd1387c"
      "74415dc880492dd1d5b9ecf3f01de48a44baeb4d3ea5cc4f8d561d0865afcabb"
      "fc14a9ab9647e6e31adabb72d792f0c9ba99dc3e9205657d28fc7771d64e6d4b");
  vector<uint8_t> encryptionIv = wvcdm::a2b_hex(
      "719dbcb253b2ec702bb8c1b1bc2f3bc6");
  vector<uint8_t> unencryptedData = wvcdm::a2b_hex(
      "19ef4361e16e6825b336e2012ad8ffc9ce176ab2256e1b98aa15b7877bd8c626"
      "fa40b2e88373457cbcf4f1b4b9793434a8ac03a708f85974cff01bddcbdd7a8e"
      "e33fd160c1d5573bfd8104efd23237edcf28205c3673920553f8dd5e916604b0"
      "1082345181dceeae5ea39d829c7f49e1850c460645de33c288723b7ae3d91a17"
      "a3f04195cd1945ba7b0f37fef7e82368be30f04365d877766f6d56f67d22a244"
      "ef2596d3053f657c1b5d90b64e11797edf1c198a23a7bfc20e4d44c74ae41280"
      "a8317f443255f4020eda850ff0954e308f53a634cbce799ae58911bc59ccd6a5"
      "de2ac53ee0fa7ea15fc692cc892acc0090865dc57becacddf362a092dfd3040b");

  // Describe the output
  uint8_t outputBuffer[256];
  OEMCrypto_DestBufferDesc destBuffer;
  destBuffer.type = OEMCrypto_BufferType_Clear;
  destBuffer.buffer.clear.address = outputBuffer;
  destBuffer.buffer.clear.max_length = sizeof(outputBuffer);

  // Decrypt the data
  sts = OEMCrypto_DecryptCTR(s.session_id(), &encryptedData[0],
                             encryptedData.size(), true, &encryptionIv[0], 0,
                             &destBuffer,
                             OEMCrypto_FirstSubsample | OEMCrypto_LastSubsample);
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);
  ASSERT_EQ(0, memcmp(&unencryptedData[0], outputBuffer,
                      unencryptedData.size()));

  s.close();
  testTearDown();
}

TEST_F(DISABLED_TestKeybox, DecryptWithOffset) {
  OEMCryptoResult sts;
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();

  s.GenerateDerivedKeys();
  s.LoadTestKeys(kDuration, 0, 0);

  // Select the key (from FillSimpleMessage)
  vector<uint8_t> keyId = wvcdm::a2b_hex("000000000000000000000000");
  sts = OEMCrypto_SelectKey(s.session_id(),
                            &keyId[0],
                            keyId.size());
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);

  // Set up our expected input and output
  vector<uint8_t> encryptedData = wvcdm::a2b_hex(
      "c17055d4e3ab8e892b40ca2deed7cd46b406cd41d50f23d5877b36"
      "ad351887df2b3774dc413904afd958ba766cc6ab51a3ffd8f845296c5d8326ee"
      "39c9d0fec79885515e6b8a12911831d9fb158ca2fd3dfcfcf228741a63734685"
      "8dffc30f5871260c5cef8be61cfa08b191c837901f077046664c0c56db81d412"
      "98b59e5655cd94871c3c226dc3565144297f1459cddba069d5d2d6206cfd5798"
      "eda4b82e01a9966d48984d6ef3fbd326ba0f6fcbe52c95786d478c2f33398c62"
      "ae5210c7472d7d8dc7d12f981679f4ea9793736f354747ef14165367b94e07fc"
      "4bcc7bd14746304fea100dc6465ab51241355bb19e6c2cfb2bb6bbf709765d13");
  vector<uint8_t> encryptionIv = wvcdm::a2b_hex(
      "c09454479a280829c946df3c22f25539");
  vector<uint8_t> unencryptedData = wvcdm::a2b_hex(
      "f344d9cfe336c94cf4e3ea9e3446d1427bc02d2debe6dec5b272b8"
      "a4004b696c4b37e01d7418510abf32bb071f9a4bc0d2ad7e874b648e50bd0e4f"
      "7085b70bf9ad2c7f37025dd45f93e90304739b1ce098a52e7b99a90f92544a9b"
      "dca6f49e0006c80a0cfa018600523ad30e483141fe720d045394815d5c875ad4"
      "b4387b8d09b6119bd0943e51b0b9103034496b3a83ba593f79baa188aeb6e08f"
      "f6475933e9ce1bb95fbb526424e7966e25830c20da73c65c6fbff110b08e4def"
      "eae94f98296770275b0d738207a8217cd6118f6ebc6e393428f2268cfedf800e"
      "a7ebc606471b9a9dfccd1589e86d88fde508261eaf190efd20554ce9e14ff3c9");

  // Describe the output
  uint8_t outputBuffer[256];
  OEMCrypto_DestBufferDesc destBuffer;
  destBuffer.type = OEMCrypto_BufferType_Clear;
  destBuffer.buffer.clear.address = outputBuffer;
  destBuffer.buffer.clear.max_length = sizeof(outputBuffer);

  // Decrypt the data
  sts = OEMCrypto_DecryptCTR(s.session_id(), &encryptedData[0],
                             encryptedData.size(), true, &encryptionIv[0], 5,
                             &destBuffer,
                             OEMCrypto_FirstSubsample | OEMCrypto_LastSubsample);
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);
  ASSERT_EQ(0, memcmp(&unencryptedData[0], outputBuffer,
                      unencryptedData.size()));

  s.close();
  testTearDown();
}

TEST_F(DISABLED_TestKeybox, DecryptUnencrypted) {
  OEMCryptoResult sts;
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();

  s.GenerateDerivedKeys();
  s.LoadTestKeys(kDuration, 0, 0);

  // Select the key (from FillSimpleMessage)
  vector<uint8_t> keyId = wvcdm::a2b_hex("000000000000000000000000");
  sts = OEMCrypto_SelectKey(s.session_id(), &keyId[0], keyId.size());
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);

  // Set up our expected input and output
  vector<uint8_t> unencryptedData = wvcdm::a2b_hex(
      "1558497b6d994be343ed1c6d6313e0537b843e9a9c0836d1e83fe33154191ce9"
      "a14d8d95bebaddc03bd471827170f527c0a166b9068b273d1bc57fbb13975ee4"
      "f6b9a31743da6c447acbb712e81b13eddfd4e96c76010ac9b8aa1b6b3152b0fc"
      "39ad33e5719656069f9ede9ebba7a77dd2e2074eec5c1b7ffc427a6f1be168f0"
      "b5857713a44623862c903284bc53417e23c65602b52c1cb699e8352453eb9698"
      "0b31459b90c26c907b549c1ab293725e414d4e45f5b30af7a55f95499a7dc89f"
      "7d13ba90b34aef6b49484b0701bf96ea8b660c24bb4e92a2d1c43beb434fa386"
      "1071380388799ac31d79285f5817687ed3e2eeb73a30744e77b757686c9ba5ad");
  vector<uint8_t> encryptionIv = wvcdm::a2b_hex(
      "49fc3efaaf614ed81d595847b928edd0");

  // Describe the output
  uint8_t outputBuffer[256];
  OEMCrypto_DestBufferDesc destBuffer;
  destBuffer.type = OEMCrypto_BufferType_Clear;
  destBuffer.buffer.clear.address = outputBuffer;
  destBuffer.buffer.clear.max_length = sizeof(outputBuffer);

  // Decrypt the data
  sts = OEMCrypto_DecryptCTR(s.session_id(), &unencryptedData[0],
                             unencryptedData.size(), false, &encryptionIv[0], 0,
                             &destBuffer,
                             OEMCrypto_FirstSubsample | OEMCrypto_LastSubsample);
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);
  ASSERT_EQ(0, memcmp(&unencryptedData[0], outputBuffer,
                      unencryptedData.size()));

  s.close();
  testTearDown();
}

TEST_F(DISABLED_TestKeybox, DecryptUnencryptedNoKey) {
  OEMCryptoResult sts;
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("NOKEY");
  s.open();

  // CLear data should be copied even if there is no key selected.

  // Set up our expected input and output
  vector<uint8_t> unencryptedData = wvcdm::a2b_hex(
      "1558497b6d994be343ed1c6d6313e0537b843e9a9c0836d1e83fe33154191ce9"
      "a14d8d95bebaddc03bd471827170f527c0a166b9068b273d1bc57fbb13975ee4"
      "f6b9a31743da6c447acbb712e81b13eddfd4e96c76010ac9b8aa1b6b3152b0fc"
      "39ad33e5719656069f9ede9ebba7a77dd2e2074eec5c1b7ffc427a6f1be168f0"
      "b5857713a44623862c903284bc53417e23c65602b52c1cb699e8352453eb9698"
      "0b31459b90c26c907b549c1ab293725e414d4e45f5b30af7a55f95499a7dc89f"
      "7d13ba90b34aef6b49484b0701bf96ea8b660c24bb4e92a2d1c43beb434fa386"
      "1071380388799ac31d79285f5817687ed3e2eeb73a30744e77b757686c9ba5ad");
  vector<uint8_t> encryptionIv = wvcdm::a2b_hex(
      "49fc3efaaf614ed81d595847b928edd0");

  // Describe the output
  uint8_t outputBuffer[256];
  OEMCrypto_DestBufferDesc destBuffer;
  destBuffer.type = OEMCrypto_BufferType_Clear;
  destBuffer.buffer.clear.address = outputBuffer;
  destBuffer.buffer.clear.max_length = sizeof(outputBuffer);

  // Decrypt the data
  sts = OEMCrypto_DecryptCTR(s.session_id(), &unencryptedData[0],
                             unencryptedData.size(), false, &encryptionIv[0], 0,
                             &destBuffer,
                             OEMCrypto_FirstSubsample | OEMCrypto_LastSubsample);
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);
  ASSERT_EQ(0, memcmp(&unencryptedData[0], outputBuffer,
                      unencryptedData.size()));

  s.close();
  testTearDown();
}

TEST_F(DISABLED_TestKeybox, DecryptSecureToClear) {
  OEMCryptoResult sts;
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();
  s.GenerateDerivedKeys();
  s.LoadTestKeys(kDuration, wvoec_mock::kControlObserveDataPath
                 | wvoec_mock::kControlDataPathSecure, 0);

  // Select the key (from FillSimpleMessage)
  vector<uint8_t> keyId = wvcdm::a2b_hex("000000000000000000000000");
  sts = OEMCrypto_SelectKey(s.session_id(), &keyId[0], keyId.size());
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);

  // Set up our expected input and output
  vector<uint8_t> encryptedData = wvcdm::a2b_hex(
      "ec261c115f9d5cda1d5cc7d33c4e37362d1397c89efdd1da5f0065c4848b0462"
      "337ba14693735203c9b4184e362439c0cea5e5d1a628425eddf8a6bf9ba901ca"
      "46f5a9fd973cffbbe3c276af9919e2e8f6f3f420538b7a0d6dc41487874d96b8"
      "efaedb45a689b91beb8c20d36140ad467d9d620b19a5fc6f223b57e0e6a7f913"
      "00fd899e5e1b89963e83067ca0912aa5b79df683e2530b55a9645be341bc5f07"
      "cffc724790af635c959e2644e51ba7f23bae710eb55a1f2f4e060c3c1dd1387c"
      "74415dc880492dd1d5b9ecf3f01de48a44baeb4d3ea5cc4f8d561d0865afcabb"
      "fc14a9ab9647e6e31adabb72d792f0c9ba99dc3e9205657d28fc7771d64e6d4b");
  vector<uint8_t> encryptionIv = wvcdm::a2b_hex(
      "719dbcb253b2ec702bb8c1b1bc2f3bc6");
  vector<uint8_t> unencryptedData = wvcdm::a2b_hex(
      "19ef4361e16e6825b336e2012ad8ffc9ce176ab2256e1b98aa15b7877bd8c626"
      "fa40b2e88373457cbcf4f1b4b9793434a8ac03a708f85974cff01bddcbdd7a8e"
      "e33fd160c1d5573bfd8104efd23237edcf28205c3673920553f8dd5e916604b0"
      "1082345181dceeae5ea39d829c7f49e1850c460645de33c288723b7ae3d91a17"
      "a3f04195cd1945ba7b0f37fef7e82368be30f04365d877766f6d56f67d22a244"
      "ef2596d3053f657c1b5d90b64e11797edf1c198a23a7bfc20e4d44c74ae41280"
      "a8317f443255f4020eda850ff0954e308f53a634cbce799ae58911bc59ccd6a5"
      "de2ac53ee0fa7ea15fc692cc892acc0090865dc57becacddf362a092dfd3040b");

  // Describe the output
  uint8_t outputBuffer[256];
  OEMCrypto_DestBufferDesc destBuffer;
  destBuffer.type = OEMCrypto_BufferType_Clear;
  destBuffer.buffer.clear.address = outputBuffer;
  destBuffer.buffer.clear.max_length = sizeof(outputBuffer);

  // Decrypt the data
  sts = OEMCrypto_DecryptCTR(s.session_id(), &encryptedData[0],
                             encryptedData.size(), true, &encryptionIv[0], 0,
                             &destBuffer,
                             OEMCrypto_FirstSubsample | OEMCrypto_LastSubsample);
  ASSERT_NE(OEMCrypto_SUCCESS, sts);
  ASSERT_NE(0, memcmp(&unencryptedData[0], outputBuffer,
                      unencryptedData.size()));

  s.close();
  testTearDown();
}

TEST_F(DISABLED_TestKeybox, KeyDuration) {
  OEMCryptoResult sts;
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();
  s.GenerateDerivedKeys();
  s.LoadTestKeys(kDuration, wvoec_mock::kControlNonceEnabled, s.get_nonce());

  // Select the key (from FillSimpleMessage)
  vector<uint8_t> keyId = wvcdm::a2b_hex("000000000000000000000000");
  sts = OEMCrypto_SelectKey(s.session_id(), &keyId[0], keyId.size());
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);

  // Set up our expected input and output
  vector<uint8_t> encryptedData = wvcdm::a2b_hex(
      "ec261c115f9d5cda1d5cc7d33c4e37362d1397c89efdd1da5f0065c4848b0462"
      "337ba14693735203c9b4184e362439c0cea5e5d1a628425eddf8a6bf9ba901ca"
      "46f5a9fd973cffbbe3c276af9919e2e8f6f3f420538b7a0d6dc41487874d96b8"
      "efaedb45a689b91beb8c20d36140ad467d9d620b19a5fc6f223b57e0e6a7f913"
      "00fd899e5e1b89963e83067ca0912aa5b79df683e2530b55a9645be341bc5f07"
      "cffc724790af635c959e2644e51ba7f23bae710eb55a1f2f4e060c3c1dd1387c"
      "74415dc880492dd1d5b9ecf3f01de48a44baeb4d3ea5cc4f8d561d0865afcabb"
      "fc14a9ab9647e6e31adabb72d792f0c9ba99dc3e9205657d28fc7771d64e6d4b");
  vector<uint8_t> encryptionIv = wvcdm::a2b_hex(
      "719dbcb253b2ec702bb8c1b1bc2f3bc6");
  vector<uint8_t> unencryptedData = wvcdm::a2b_hex(
      "19ef4361e16e6825b336e2012ad8ffc9ce176ab2256e1b98aa15b7877bd8c626"
      "fa40b2e88373457cbcf4f1b4b9793434a8ac03a708f85974cff01bddcbdd7a8e"
      "e33fd160c1d5573bfd8104efd23237edcf28205c3673920553f8dd5e916604b0"
      "1082345181dceeae5ea39d829c7f49e1850c460645de33c288723b7ae3d91a17"
      "a3f04195cd1945ba7b0f37fef7e82368be30f04365d877766f6d56f67d22a244"
      "ef2596d3053f657c1b5d90b64e11797edf1c198a23a7bfc20e4d44c74ae41280"
      "a8317f443255f4020eda850ff0954e308f53a634cbce799ae58911bc59ccd6a5"
      "de2ac53ee0fa7ea15fc692cc892acc0090865dc57becacddf362a092dfd3040b");

  // Describe the output
  uint8_t outputBuffer[256];
  OEMCrypto_DestBufferDesc destBuffer;
  destBuffer.type = OEMCrypto_BufferType_Clear;
  destBuffer.buffer.clear.address = outputBuffer;
  destBuffer.buffer.clear.max_length = sizeof(outputBuffer);
  // Decrypt the data
  sts = OEMCrypto_DecryptCTR(s.session_id(), &encryptedData[0],
                             encryptedData.size(), true, &encryptionIv[0], 0,
                             &destBuffer,
                             OEMCrypto_FirstSubsample | OEMCrypto_LastSubsample);
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);
  ASSERT_EQ(0, memcmp(&unencryptedData[0], outputBuffer,
                      unencryptedData.size()));

  sleep(kShortSleep);  //  Should still be valid key.

  memset(outputBuffer, 0, sizeof(outputBuffer));
  destBuffer.type = OEMCrypto_BufferType_Clear;
  destBuffer.buffer.clear.address = outputBuffer;
  destBuffer.buffer.clear.max_length = sizeof(outputBuffer);

  // Decrypt the data
  sts = OEMCrypto_DecryptCTR(s.session_id(), &encryptedData[0],
                             encryptedData.size(), true, &encryptionIv[0], 0,
                             &destBuffer,
                             OEMCrypto_FirstSubsample | OEMCrypto_LastSubsample);
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);
  ASSERT_EQ(0, memcmp(&unencryptedData[0], outputBuffer,
                      unencryptedData.size()));

  sleep(kLongSleep);  // Should be expired key.

  memset(outputBuffer, 0, sizeof(outputBuffer));
  destBuffer.type = OEMCrypto_BufferType_Clear;
  destBuffer.buffer.clear.address = outputBuffer;
  destBuffer.buffer.clear.max_length = sizeof(outputBuffer);

  // Decrypt the data
  sts = OEMCrypto_DecryptCTR(s.session_id(), &encryptedData[0],
                             encryptedData.size(), true, &encryptionIv[0], 0,
                             &destBuffer,
                             OEMCrypto_FirstSubsample | OEMCrypto_LastSubsample);
  ASSERT_NE(OEMCrypto_SUCCESS, sts);
  ASSERT_NE(0, memcmp(&unencryptedData[0], outputBuffer,
                      unencryptedData.size()));

  s.close();
  testTearDown();
}

///////////////////////////////////////////////////
// Certificate Root of Trust Tests
///////////////////////////////////////////////////

void TestKey(const uint8_t key[], size_t length) {
  uint8_t const* p = key;
  RSA* rsa = d2i_RSAPrivateKey(0, &p , length);
  if (!rsa) {
    cout << "d2i_RSAPrivateKey failed. ";
    dump_openssl_error();
    ASSERT_TRUE(false);
  }
  switch (RSA_check_key(rsa)) {
  case 1:  // valid.
    ASSERT_TRUE(true);
    return;
  case 0:  // not valid.
    cout << "[TestKey(): rsa key not valid] ";
    dump_openssl_error();
    ASSERT_TRUE(false);
  default:  // -1 == check failed.
    cout << "[TestKey(): error checking rsa key] ";
    dump_openssl_error();
    ASSERT_TRUE(false);
  }
}
TEST_F(DISABLED_TestKeybox, ValidateRSATestKeys) {
  TestKey(kTestPKCS1RSAPrivateKey2_2048, sizeof(kTestPKCS1RSAPrivateKey2_2048));
  TestKey(kTestPKCS1RSAPrivateKey3_2048, sizeof(kTestPKCS1RSAPrivateKey3_2048));
}

TEST_F(DISABLED_TestKeybox, CertificateProvision) {
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();
  s.GenerateDerivedKeys();
  struct RSAPrivateKeyMessage encrypted;
  std::vector<uint8_t> signature;
  s.MakeRSACertificate(&encrypted, &signature);
  vector<uint8_t> wrapped_key;
  s.RewrapRSAKey(encrypted, signature, &wrapped_key);

  vector<uint8_t> clear_key(kTestRSAPKCS8PrivateKeyInfo2_2048,
                            kTestRSAPKCS8PrivateKeyInfo2_2048
                            + sizeof(kTestRSAPKCS8PrivateKeyInfo2_2048));
  ASSERT_EQ(NULL, find(wrapped_key, clear_key));

  s.close();
  testTearDown();
}

TEST_F(DISABLED_TestKeybox, CertificateProvisionBadRange1) {
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();
  s.GenerateDerivedKeys();
  struct RSAPrivateKeyMessage encrypted;
  std::vector<uint8_t> signature;
  s.MakeRSACertificate(&encrypted, &signature);
  vector<uint8_t> wrapped_key;

  size_t wrapped_key_length = 0;
  const uint8_t* message_ptr = reinterpret_cast<const uint8_t*>(&encrypted);
  ASSERT_EQ(OEMCrypto_ERROR_SHORT_BUFFER,
            OEMCrypto_RewrapDeviceRSAKey(s.session_id(), message_ptr,
                                         sizeof(encrypted), &signature[0],
                                         signature.size(), &encrypted.nonce,
                                         encrypted.rsa_key,
                                         encrypted.rsa_key_length,
                                         encrypted.rsa_key_iv, NULL,
                                         &wrapped_key_length));
  wrapped_key.clear();
  wrapped_key.resize(wrapped_key_length);
  uint32_t nonce = encrypted.nonce;
  ASSERT_NE(OEMCrypto_SUCCESS,
            OEMCrypto_RewrapDeviceRSAKey(s.session_id(), message_ptr,
                                         sizeof(encrypted), &signature[0],
                                         signature.size(), &nonce,
                                         encrypted.rsa_key,
                                         encrypted.rsa_key_length,
                                         encrypted.rsa_key_iv,
                                         & (wrapped_key.front()),
                                         &wrapped_key_length));
  s.close();
  testTearDown();
}

TEST_F(DISABLED_TestKeybox, CertificateProvisionBadRange2) {
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();
  s.GenerateDerivedKeys();
  struct RSAPrivateKeyMessage encrypted;
  std::vector<uint8_t> signature;
  s.MakeRSACertificate(&encrypted, &signature);
  vector<uint8_t> wrapped_key;

  size_t wrapped_key_length = 0;
  const uint8_t* message_ptr = reinterpret_cast<const uint8_t*>(&encrypted);
  ASSERT_EQ(OEMCrypto_ERROR_SHORT_BUFFER,
            OEMCrypto_RewrapDeviceRSAKey(s.session_id(), message_ptr,
                                         sizeof(encrypted), &signature[0],
                                         signature.size(), &encrypted.nonce,
                                         encrypted.rsa_key,
                                         encrypted.rsa_key_length,
                                         encrypted.rsa_key_iv, NULL,
                                         &wrapped_key_length));
  wrapped_key.clear();
  wrapped_key.resize(wrapped_key_length);
  vector<uint8_t> bad_buffer(encrypted.rsa_key,
                             encrypted.rsa_key+sizeof(encrypted.rsa_key));

  ASSERT_NE(OEMCrypto_SUCCESS,
            OEMCrypto_RewrapDeviceRSAKey(s.session_id(), message_ptr,
                                         sizeof(encrypted), &signature[0],
                                         signature.size(), &encrypted.nonce,
                                         &bad_buffer[0],
                                         encrypted.rsa_key_length,
                                         encrypted.rsa_key_iv,
                                         & (wrapped_key.front()),
                                         &wrapped_key_length));
  s.close();
  testTearDown();
}

TEST_F(DISABLED_TestKeybox, CertificateProvisionBadRange3) {
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();
  s.GenerateDerivedKeys();
  struct RSAPrivateKeyMessage encrypted;
  std::vector<uint8_t> signature;
  s.MakeRSACertificate(&encrypted, &signature);
  vector<uint8_t> wrapped_key;

  size_t wrapped_key_length = 0;
  const uint8_t* message_ptr = reinterpret_cast<const uint8_t*>(&encrypted);
  ASSERT_EQ(OEMCrypto_ERROR_SHORT_BUFFER,
            OEMCrypto_RewrapDeviceRSAKey(s.session_id(), message_ptr,
                                         sizeof(encrypted), &signature[0],
                                         signature.size(), &encrypted.nonce,
                                         encrypted.rsa_key,
                                         encrypted.rsa_key_length,
                                         encrypted.rsa_key_iv, NULL,
                                         &wrapped_key_length));
  wrapped_key.clear();
  wrapped_key.resize(wrapped_key_length);
  vector<uint8_t> bad_buffer(encrypted.rsa_key,
                             encrypted.rsa_key+sizeof(encrypted.rsa_key));

  ASSERT_NE(OEMCrypto_SUCCESS,
            OEMCrypto_RewrapDeviceRSAKey(s.session_id(), message_ptr,
                                         sizeof(encrypted), &signature[0],
                                         signature.size(), &encrypted.nonce,
                                         encrypted.rsa_key,
                                         encrypted.rsa_key_length,
                                         &bad_buffer[0],
                                         & (wrapped_key.front()),
                                         &wrapped_key_length));
  s.close();
  testTearDown();
}

TEST_F(DISABLED_TestKeybox, CertificateProvisionBadSignature) {
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();
  s.GenerateDerivedKeys();
  struct RSAPrivateKeyMessage encrypted;
  std::vector<uint8_t> signature;
  s.MakeRSACertificate(&encrypted, &signature);
  vector<uint8_t> wrapped_key;

  size_t wrapped_key_length = 0;
  const uint8_t* message_ptr = reinterpret_cast<const uint8_t*>(&encrypted);
  ASSERT_EQ(OEMCrypto_ERROR_SHORT_BUFFER,
            OEMCrypto_RewrapDeviceRSAKey(s.session_id(), message_ptr,
                                         sizeof(encrypted), &signature[0],
                                         signature.size(), &encrypted.nonce,
                                         encrypted.rsa_key,
                                         encrypted.rsa_key_length,
                                         encrypted.rsa_key_iv, NULL,
                                         &wrapped_key_length));
  wrapped_key.clear();
  wrapped_key.resize(wrapped_key_length);
  signature[4] ^= 42;  // bad signature.
  ASSERT_NE(OEMCrypto_SUCCESS,
            OEMCrypto_RewrapDeviceRSAKey(s.session_id(), message_ptr,
                                         sizeof(encrypted), &signature[0],
                                         signature.size(), &encrypted.nonce,
                                         encrypted.rsa_key,
                                         encrypted.rsa_key_length,
                                         encrypted.rsa_key_iv,
                                         & (wrapped_key.front()),
                                         &wrapped_key_length));
  s.close();
  testTearDown();
}

TEST_F(DISABLED_TestKeybox, CertificateProvisionBadNonce) {
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();
  s.GenerateDerivedKeys();
  struct RSAPrivateKeyMessage encrypted;
  std::vector<uint8_t> signature;
  s.MakeRSACertificate(&encrypted, &signature);
  vector<uint8_t> wrapped_key;

  size_t wrapped_key_length = 0;
  const uint8_t* message_ptr = reinterpret_cast<const uint8_t*>(&encrypted);
  ASSERT_EQ(OEMCrypto_ERROR_SHORT_BUFFER,
            OEMCrypto_RewrapDeviceRSAKey(s.session_id(), message_ptr,
                                         sizeof(encrypted), &signature[0],
                                         signature.size(), &encrypted.nonce,
                                         encrypted.rsa_key,
                                         encrypted.rsa_key_length,
                                         encrypted.rsa_key_iv, NULL,
                                         &wrapped_key_length));
  wrapped_key.clear();
  wrapped_key.resize(wrapped_key_length);
  encrypted.nonce ^= 42;  // Almost surely a bad nonce.
  ASSERT_NE(OEMCrypto_SUCCESS,
            OEMCrypto_RewrapDeviceRSAKey(s.session_id(), message_ptr,
                                         sizeof(encrypted), &signature[0],
                                         signature.size(), &encrypted.nonce,
                                         encrypted.rsa_key,
                                         encrypted.rsa_key_length,
                                         encrypted.rsa_key_iv,
                                         & (wrapped_key.front()),
                                         &wrapped_key_length));
  s.close();
  testTearDown();
}

TEST_F(DISABLED_TestKeybox, CertificateProvisionBadRSAKey) {
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();
  s.GenerateDerivedKeys();
  struct RSAPrivateKeyMessage encrypted;
  std::vector<uint8_t> signature;
  s.MakeRSACertificate(&encrypted, &signature);
  vector<uint8_t> wrapped_key;

  size_t wrapped_key_length = 0;
  const uint8_t* message_ptr = reinterpret_cast<const uint8_t*>(&encrypted);
  ASSERT_EQ(OEMCrypto_ERROR_SHORT_BUFFER,
            OEMCrypto_RewrapDeviceRSAKey(s.session_id(), message_ptr,
                                         sizeof(encrypted), &signature[0],
                                         signature.size(), &encrypted.nonce,
                                         encrypted.rsa_key,
                                         encrypted.rsa_key_length,
                                         encrypted.rsa_key_iv, NULL,
                                         &wrapped_key_length));
  wrapped_key.clear();
  wrapped_key.resize(wrapped_key_length);
  encrypted.rsa_key[1] ^= 42;  // Almost surely a bad key.
  ASSERT_NE(OEMCrypto_SUCCESS,
            OEMCrypto_RewrapDeviceRSAKey(s.session_id(), message_ptr,
                                         sizeof(encrypted), &signature[0],
                                         signature.size(), &encrypted.nonce,
                                         encrypted.rsa_key,
                                         encrypted.rsa_key_length,
                                         encrypted.rsa_key_iv,
                                         & (wrapped_key.front()),
                                         &wrapped_key_length));
  s.close();
  testTearDown();
}

TEST_F(DISABLED_TestKeybox, LoadWrappedRSAKey) {
  OEMCryptoResult sts;
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  std::vector<uint8_t> wrapped_rsa_key;
  CreateWrappedRSAKey(&wrapped_rsa_key);

  Session& s = createSession("ONE");
  s.open();
  sts = OEMCrypto_LoadDeviceRSAKey(s.session_id(), &wrapped_rsa_key[0],
                                   wrapped_rsa_key.size());
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);
  s.close();
  testTearDown();
}

TEST_F(DISABLED_TestKeybox, RSASignature) {
  OEMCryptoResult sts;
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  std::vector<uint8_t> wrapped_rsa_key;
  CreateWrappedRSAKey(&wrapped_rsa_key);

  Session& s = createSession("ONE");
  s.open();
  sts = OEMCrypto_LoadDeviceRSAKey(s.session_id(), &wrapped_rsa_key[0],
                                   wrapped_rsa_key.size());
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);

  // Sign a Message
  vector<uint8_t> licenseRequest = wvcdm::a2b_hex(
      "ba711a51e0c4c995440c28057f7f5e2f2e9c3a1edeb7549aca21e6050b059ac8"
      "6ad64ec1a528eef17b4f5ce781af488d50fb0e60d04b48c78d55847a4e14243c"
      "0023c553b46a2f53995870f351295e3aa2237f153f1415e817ad23e662e547b1"
      "4708b303473813f93ee192353ff22bee54dd0f558bbe4b61b75b387bc310e9d6"
      "8ff2cb3482689c0688570809b756dba4c2697be3132a2da782aa877ed64d8c7d"
      "506525a382bad14d7e797c256c3617c22fa4165482b9742e9b54ffb6c52eda1d");
  size_t signature_length = 0;

  sts = OEMCrypto_GenerateRSASignature(s.session_id(), &licenseRequest[0],
                                       licenseRequest.size(), NULL,
                                       &signature_length);

  ASSERT_EQ(OEMCrypto_ERROR_SHORT_BUFFER, sts);
  ASSERT_NE(static_cast<size_t>(0), signature_length);

  uint8_t* signature = new uint8_t[signature_length];

  sts = OEMCrypto_GenerateRSASignature(s.session_id(), &licenseRequest[0],
                                       licenseRequest.size(), signature,
                                       &signature_length);

  ASSERT_EQ(OEMCrypto_SUCCESS, sts);
  // In the real world, the signature above would just have been used to contact
  // the license server to get this response.
  ASSERT_TRUE(s.PreparePublicKey(kTestRSAPublicKey2_2048,
                                 sizeof(kTestRSAPublicKey2_2048)));
  ASSERT_TRUE(s.VerifyRSASignature(&licenseRequest[0], licenseRequest.size(),
                                   signature, &signature_length));
  s.close();
  testTearDown();

  delete[] signature;
}

TEST_F(DISABLED_TestKeybox, LoadRSASessionKey) {
  testSetUp();

  InstallKeybox(kDefaultKeybox, true);
  std::vector<uint8_t> wrapped_rsa_key;
  CreateWrappedRSAKey(&wrapped_rsa_key);
  Session& s = createSession("ONE");
  s.open();
  s.InstallRSASessionTestKey(wrapped_rsa_key);
  s.close();
  testTearDown();
}

TEST_F(DISABLED_TestKeybox, CertificateDecrypt) {
  OEMCryptoResult sts;
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  std::vector<uint8_t> wrapped_rsa_key;
  CreateWrappedRSAKey(&wrapped_rsa_key);
  Session& s = createSession("ONE");
  s.open();

  s.InstallRSASessionTestKey(wrapped_rsa_key);
  s.LoadTestKeys(kDuration, 0, 0);

  // Select the key (from FillSimpleMessage)
  vector<uint8_t> keyId = wvcdm::a2b_hex("000000000000000000000000");
  sts = OEMCrypto_SelectKey(s.session_id(), &keyId[0], keyId.size());
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);

  // Set up our expected input and output
  vector<uint8_t> encryptedData = wvcdm::a2b_hex(
      "ec261c115f9d5cda1d5cc7d33c4e37362d1397c89efdd1da5f0065c4848b0462"
      "337ba14693735203c9b4184e362439c0cea5e5d1a628425eddf8a6bf9ba901ca"
      "46f5a9fd973cffbbe3c276af9919e2e8f6f3f420538b7a0d6dc41487874d96b8"
      "efaedb45a689b91beb8c20d36140ad467d9d620b19a5fc6f223b57e0e6a7f913"
      "00fd899e5e1b89963e83067ca0912aa5b79df683e2530b55a9645be341bc5f07"
      "cffc724790af635c959e2644e51ba7f23bae710eb55a1f2f4e060c3c1dd1387c"
      "74415dc880492dd1d5b9ecf3f01de48a44baeb4d3ea5cc4f8d561d0865afcabb"
      "fc14a9ab9647e6e31adabb72d792f0c9ba99dc3e9205657d28fc7771d64e6d4b");
  vector<uint8_t> encryptionIv = wvcdm::a2b_hex(
      "719dbcb253b2ec702bb8c1b1bc2f3bc6");
  vector<uint8_t> unencryptedData = wvcdm::a2b_hex(
      "19ef4361e16e6825b336e2012ad8ffc9ce176ab2256e1b98aa15b7877bd8c626"
      "fa40b2e88373457cbcf4f1b4b9793434a8ac03a708f85974cff01bddcbdd7a8e"
      "e33fd160c1d5573bfd8104efd23237edcf28205c3673920553f8dd5e916604b0"
      "1082345181dceeae5ea39d829c7f49e1850c460645de33c288723b7ae3d91a17"
      "a3f04195cd1945ba7b0f37fef7e82368be30f04365d877766f6d56f67d22a244"
      "ef2596d3053f657c1b5d90b64e11797edf1c198a23a7bfc20e4d44c74ae41280"
      "a8317f443255f4020eda850ff0954e308f53a634cbce799ae58911bc59ccd6a5"
      "de2ac53ee0fa7ea15fc692cc892acc0090865dc57becacddf362a092dfd3040b");

  // Describe the output
  uint8_t outputBuffer[256];
  OEMCrypto_DestBufferDesc destBuffer;
  destBuffer.type = OEMCrypto_BufferType_Clear;
  destBuffer.buffer.clear.address = outputBuffer;
  destBuffer.buffer.clear.max_length = sizeof(outputBuffer);

  // Decrypt the data
  sts = OEMCrypto_DecryptCTR(s.session_id(), &encryptedData[0],
                             encryptedData.size(), true, &encryptionIv[0], 0,
                             &destBuffer,
                             OEMCrypto_FirstSubsample | OEMCrypto_LastSubsample);
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);
  ASSERT_EQ(0, memcmp(&unencryptedData[0], outputBuffer,
                      unencryptedData.size()));

  s.close();
  testTearDown();
}

class DISABLED_GenericDRMTest : public DISABLED_TestKeybox {
 protected:
  MessageData message_data_;

  static const size_t kBufferSize = 160;  // multiple of encryption block size.
  uint8_t clear_buffer_[kBufferSize];
  uint8_t encrypted_buffer_[kBufferSize];
  uint8_t iv_[wvcdm::KEY_IV_SIZE];


  void MakeFourKeys(Session* s) {
    s->FillSimpleMessage(&message_data_, kDuration, 0, 0);
    message_data_.keys[0].control.control_bits = htonl(wvoec_mock::kControlAllowEncrypt);
    message_data_.keys[1].control.control_bits = htonl(wvoec_mock::kControlAllowDecrypt);
    message_data_.keys[2].control.control_bits = htonl(wvoec_mock::kControlAllowSign);
    message_data_.keys[3].control.control_bits = htonl(wvoec_mock::kControlAllowVerify);

    message_data_.keys[2].key_data_length = wvcdm::MAC_KEY_SIZE;
    message_data_.keys[3].key_data_length = wvcdm::MAC_KEY_SIZE;

    for(size_t i=0; i < kBufferSize; i++) {
      clear_buffer_[i] = 1 + i %250;
    }
    for(size_t i=0; i < wvcdm::KEY_IV_SIZE; i++) {
      iv_[i] = i;
    }

  }

  void LoadFourKeys(Session* s) {
    MessageData encrypted;
    s->EncryptMessage(message_data_, &encrypted);
    std::vector<uint8_t> signature;
    s->ServerSignMessage(encrypted, &signature);
    OEMCrypto_KeyObject key_array[kNumKeys];
    const uint8_t* message_ptr = reinterpret_cast<const uint8_t*>(&encrypted);
    s->FillKeyArray(encrypted, key_array);

    OEMCryptoResult sts = OEMCrypto_LoadKeys(s->session_id(),
                                             message_ptr, sizeof(encrypted),
                                             &signature[0], signature.size(),
                                             encrypted.mac_key_iv,
                                             encrypted.mac_keys,
                                             kNumKeys, key_array);
    ASSERT_EQ(OEMCrypto_SUCCESS, sts);
  }

  void EncryptBuffer(unsigned int key_index, const uint8_t* in_buffer,
                     uint8_t *out_buffer) {

    AES_KEY aes_key;
    ASSERT_EQ(0, AES_set_encrypt_key(message_data_.keys[key_index].key_data,
                                     AES_BLOCK_SIZE * 8, &aes_key));
    uint8_t iv_buffer[wvcdm::KEY_IV_SIZE];
    memcpy(iv_buffer, iv_, wvcdm::KEY_IV_SIZE);
    AES_cbc_encrypt(in_buffer, out_buffer, kBufferSize,
                    &aes_key, iv_buffer, AES_ENCRYPT);
  }

  // Sign the buffer with the specified key.
  void SignBuffer(unsigned int key_index, const uint8_t* in_buffer,
                  uint8_t signature[SHA256_DIGEST_LENGTH]) {
    unsigned int md_len = SHA256_DIGEST_LENGTH;
    HMAC(EVP_sha256(), message_data_.keys[key_index].key_data,
         SHA256_DIGEST_LENGTH, in_buffer, kBufferSize, signature, &md_len);
  }

  void BadEncrypt(unsigned int key_index, OEMCrypto_Algorithm algorithm,
                  size_t buffer_length) {
    OEMCryptoResult sts;
    InstallKeybox(kDefaultKeybox, true);
    Session& s = createSession("ONE");
    s.open();
    s.GenerateDerivedKeys();
    MakeFourKeys(&s);
    LoadFourKeys(&s);
    uint8_t expected_encrypted[kBufferSize];
    EncryptBuffer(key_index, clear_buffer_, expected_encrypted);
    sts = OEMCrypto_SelectKey(s.session_id(),
                              message_data_.keys[key_index].key_id,
                              kTestKeyIdLength);
    ASSERT_EQ(OEMCrypto_SUCCESS, sts);
    uint8_t encrypted[kBufferSize];
    sts = OEMCrypto_Generic_Encrypt(s.session_id(), clear_buffer_,
                                    buffer_length, iv_,
                                    algorithm, encrypted);
    ASSERT_NE(OEMCrypto_SUCCESS, sts);
    ASSERT_NE(0, memcmp(encrypted, expected_encrypted, buffer_length));
    s.close();
  }

  void BadDecrypt(unsigned int key_index, OEMCrypto_Algorithm algorithm,
                  size_t buffer_length) {
    OEMCryptoResult sts;
    InstallKeybox(kDefaultKeybox, true);
    Session& s = createSession("ONE");
    s.open();
    s.GenerateDerivedKeys();
    MakeFourKeys(&s);
    LoadFourKeys(&s);
    uint8_t encrypted[kBufferSize];
    EncryptBuffer(key_index, clear_buffer_, encrypted);
    sts = OEMCrypto_SelectKey(s.session_id(),
                              message_data_.keys[key_index].key_id,
                              kTestKeyIdLength);
    ASSERT_EQ(OEMCrypto_SUCCESS, sts);
    uint8_t resultant[kBufferSize];
    sts = OEMCrypto_Generic_Decrypt(s.session_id(), encrypted,
                                    buffer_length, iv_,
                                    algorithm, resultant);
    ASSERT_NE(OEMCrypto_SUCCESS, sts);
    ASSERT_NE(0, memcmp(clear_buffer_, resultant, buffer_length));
    s.close();
  }

  void BadSign(unsigned int key_index, OEMCrypto_Algorithm algorithm) {
    OEMCryptoResult sts;
    InstallKeybox(kDefaultKeybox, true);
    Session& s = createSession("ONE");
    s.open();
    s.GenerateDerivedKeys();
    MakeFourKeys(&s);
    LoadFourKeys(&s);
    uint8_t expected_signature[SHA256_DIGEST_LENGTH];
    SignBuffer(key_index, clear_buffer_, expected_signature);

    sts = OEMCrypto_SelectKey(s.session_id(),
                              message_data_.keys[key_index].key_id,
                              kTestKeyIdLength);
    ASSERT_EQ(OEMCrypto_SUCCESS, sts);
    size_t signature_length = (size_t)SHA256_DIGEST_LENGTH;
    uint8_t signature[SHA256_DIGEST_LENGTH];
    sts = OEMCrypto_Generic_Sign(s.session_id(), clear_buffer_, kBufferSize,
                                 algorithm, signature, &signature_length);
    ASSERT_NE(OEMCrypto_SUCCESS, sts);
    ASSERT_NE(0, memcmp(signature, expected_signature, SHA256_DIGEST_LENGTH));
    s.close();
  }

  void BadVerify(unsigned int key_index, OEMCrypto_Algorithm algorithm,
                 size_t signature_size, bool alter_data) {
    OEMCryptoResult sts;
    InstallKeybox(kDefaultKeybox, true);
    Session& s = createSession("ONE");
    s.open();
    s.GenerateDerivedKeys();
    MakeFourKeys(&s);
    LoadFourKeys(&s);
    uint8_t signature[SHA256_DIGEST_LENGTH];
    SignBuffer(key_index, clear_buffer_, signature);
    if( alter_data ) {
      signature[0] = 43;
    }

    sts = OEMCrypto_SelectKey(s.session_id(),
                              message_data_.keys[key_index].key_id,
                              kTestKeyIdLength);
    ASSERT_EQ(OEMCrypto_SUCCESS, sts);
    sts = OEMCrypto_Generic_Verify(s.session_id(), clear_buffer_, kBufferSize,
                                   algorithm,signature,
                                   signature_size);
    ASSERT_NE(OEMCrypto_SUCCESS, sts);
    s.close();
  }
};

TEST_F(DISABLED_GenericDRMTest, GenericKeyLoad) {
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();
  s.GenerateDerivedKeys();
  MakeFourKeys(&s);
  LoadFourKeys(&s);

  s.close();
  testTearDown();
}

TEST_F(DISABLED_GenericDRMTest, GenericKeyEncrypt) {
  OEMCryptoResult sts;
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();
  s.GenerateDerivedKeys();
  MakeFourKeys(&s);
  LoadFourKeys(&s);
  unsigned int key_index = 0;
  uint8_t expected_encrypted[kBufferSize];
  EncryptBuffer(key_index, clear_buffer_, expected_encrypted);
  sts = OEMCrypto_SelectKey(s.session_id(),
                            message_data_.keys[key_index].key_id,
                            kTestKeyIdLength);
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);
  uint8_t encrypted[kBufferSize];
  sts = OEMCrypto_Generic_Encrypt(s.session_id(), clear_buffer_, kBufferSize, iv_,
                                  OEMCrypto_AES_CBC_128_NO_PADDING, encrypted);
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);
  ASSERT_EQ(0, memcmp(encrypted, expected_encrypted, kBufferSize));
  s.close();
  testTearDown();
}


TEST_F(DISABLED_GenericDRMTest, GenericKeyBadEncrypt) {
  testSetUp();
  BadEncrypt(0, OEMCrypto_HMAC_SHA256, kBufferSize);
  BadEncrypt(0, OEMCrypto_AES_CBC_128_NO_PADDING, kBufferSize-10);
  BadEncrypt(1, OEMCrypto_AES_CBC_128_NO_PADDING, kBufferSize);
  BadEncrypt(2, OEMCrypto_AES_CBC_128_NO_PADDING, kBufferSize);
  BadEncrypt(3, OEMCrypto_AES_CBC_128_NO_PADDING, kBufferSize);
  testTearDown();
}

TEST_F(DISABLED_GenericDRMTest, GenericKeyDecrypt) {
  OEMCryptoResult sts;
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();
  s.GenerateDerivedKeys();
  MakeFourKeys(&s);
  LoadFourKeys(&s);
  unsigned int key_index = 1;
  uint8_t encrypted[kBufferSize];
  EncryptBuffer(key_index, clear_buffer_, encrypted);
  sts = OEMCrypto_SelectKey(s.session_id(), message_data_.keys[key_index].key_id,
                            kTestKeyIdLength);
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);
  uint8_t resultant[kBufferSize];
  sts = OEMCrypto_Generic_Decrypt(s.session_id(), encrypted, kBufferSize, iv_,
                                  OEMCrypto_AES_CBC_128_NO_PADDING, resultant);
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);
  ASSERT_EQ(0, memcmp(clear_buffer_, resultant, kBufferSize));
  s.close();
  testTearDown();
}

TEST_F(DISABLED_GenericDRMTest, GenericSecureToClear) {
  OEMCryptoResult sts;
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();
  s.GenerateDerivedKeys();
  MakeFourKeys(&s);
  message_data_.keys[1].control.control_bits
      |= htonl(wvoec_mock::kControlObserveDataPath
               | wvoec_mock::kControlDataPathSecure);
  LoadFourKeys(&s);
  unsigned int key_index = 1;
  uint8_t encrypted[kBufferSize];
  EncryptBuffer(key_index, clear_buffer_, encrypted);
  sts = OEMCrypto_SelectKey(s.session_id(), message_data_.keys[key_index].key_id,
                            kTestKeyIdLength);
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);
  uint8_t resultant[kBufferSize];
  sts = OEMCrypto_Generic_Decrypt(s.session_id(), encrypted, kBufferSize, iv_,
                                  OEMCrypto_AES_CBC_128_NO_PADDING, resultant);
  ASSERT_NE(OEMCrypto_SUCCESS, sts);
  ASSERT_NE(0, memcmp(clear_buffer_, resultant, kBufferSize));
  s.close();
  testTearDown();
}


TEST_F(DISABLED_GenericDRMTest, GenericKeyBadDecrypt) {
  testSetUp();
  BadDecrypt(1, OEMCrypto_HMAC_SHA256, kBufferSize);
  BadDecrypt(1, OEMCrypto_AES_CBC_128_NO_PADDING, kBufferSize-10);
  BadDecrypt(0, OEMCrypto_AES_CBC_128_NO_PADDING, kBufferSize);
  BadDecrypt(2, OEMCrypto_AES_CBC_128_NO_PADDING, kBufferSize);
  BadDecrypt(3, OEMCrypto_AES_CBC_128_NO_PADDING, kBufferSize);
  testTearDown();
}

TEST_F(DISABLED_GenericDRMTest, GenericKeySign) {
  OEMCryptoResult sts;
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();
  s.GenerateDerivedKeys();
  MakeFourKeys(&s);
  LoadFourKeys(&s);
  unsigned int key_index = 2;
  uint8_t expected_signature[SHA256_DIGEST_LENGTH];
  SignBuffer(key_index, clear_buffer_, expected_signature);

  sts = OEMCrypto_SelectKey(s.session_id(), message_data_.keys[key_index].key_id,
                            kTestKeyIdLength);
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);
  size_t gen_signature_length = 0;
  sts = OEMCrypto_Generic_Sign(s.session_id(), clear_buffer_, kBufferSize,
                               OEMCrypto_HMAC_SHA256, NULL,
                               &gen_signature_length);
  ASSERT_EQ(OEMCrypto_ERROR_SHORT_BUFFER, sts);
  ASSERT_EQ(static_cast<size_t>(SHA256_DIGEST_LENGTH), gen_signature_length);
  uint8_t signature[SHA256_DIGEST_LENGTH];
  sts = OEMCrypto_Generic_Sign(s.session_id(), clear_buffer_, kBufferSize,
                               OEMCrypto_HMAC_SHA256,signature,
                               &gen_signature_length);
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);
  ASSERT_EQ(0, memcmp(signature, expected_signature, SHA256_DIGEST_LENGTH));
  s.close();
  testTearDown();
}

TEST_F(DISABLED_GenericDRMTest, GenericKeyBadSign) {
  testSetUp();
  BadSign(0, OEMCrypto_HMAC_SHA256);  // Can't sign with encrypt key.
  BadSign(1, OEMCrypto_HMAC_SHA256);  // Can't sign with decrypt key.
  BadSign(3, OEMCrypto_HMAC_SHA256);  // Can't sign with verify key.
  BadSign(2, OEMCrypto_AES_CBC_128_NO_PADDING);  // Bad signing algorithm.
  testTearDown();
}

TEST_F(DISABLED_GenericDRMTest, GenericKeyVerify) {
  OEMCryptoResult sts;
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();
  s.GenerateDerivedKeys();
  MakeFourKeys(&s);
  LoadFourKeys(&s);
  unsigned int key_index = 3;
  uint8_t signature[SHA256_DIGEST_LENGTH];
  SignBuffer(key_index, clear_buffer_, signature);

  sts = OEMCrypto_SelectKey(s.session_id(), message_data_.keys[key_index].key_id,
                            kTestKeyIdLength);
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);
  sts = OEMCrypto_Generic_Verify(s.session_id(), clear_buffer_, kBufferSize,
                                 OEMCrypto_HMAC_SHA256,signature,
                                 SHA256_DIGEST_LENGTH);
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);
  s.close();
  testTearDown();
}

TEST_F(DISABLED_GenericDRMTest, GenericKeyBadVerify) {
  testSetUp();
  BadVerify(0, OEMCrypto_HMAC_SHA256, SHA256_DIGEST_LENGTH, false);
  BadVerify(1, OEMCrypto_HMAC_SHA256, SHA256_DIGEST_LENGTH, false);
  BadVerify(2, OEMCrypto_HMAC_SHA256, SHA256_DIGEST_LENGTH, false);
  BadVerify(3, OEMCrypto_HMAC_SHA256, SHA256_DIGEST_LENGTH, true);
  BadVerify(3, OEMCrypto_HMAC_SHA256, SHA256_DIGEST_LENGTH - 1, false);
  BadVerify(3, OEMCrypto_HMAC_SHA256, SHA256_DIGEST_LENGTH + 1, false);
  BadVerify(3, OEMCrypto_AES_CBC_128_NO_PADDING, SHA256_DIGEST_LENGTH, false);
  testTearDown();
}

TEST_F(DISABLED_GenericDRMTest, KeyDurationEncrypt) {
  OEMCryptoResult sts;
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();
  s.GenerateDerivedKeys();
  MakeFourKeys(&s);
  message_data_.keys[0].control.duration = htonl(kDuration);
  message_data_.keys[1].control.duration = htonl(kDuration);
  message_data_.keys[2].control.duration = htonl(kDuration);
  message_data_.keys[3].control.duration = htonl(kDuration);
  LoadFourKeys(&s);

  uint8_t expected_encrypted[kBufferSize];
  EncryptBuffer(0, clear_buffer_, expected_encrypted);
  unsigned int key_index = 0;
  uint8_t encrypted[kBufferSize];

  sleep(kShortSleep);  //  Should still be valid key.

  memset(encrypted, 0, kBufferSize);
  sts = OEMCrypto_SelectKey(s.session_id(), message_data_.keys[key_index].key_id,
                            kTestKeyIdLength);
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);
  sts = OEMCrypto_Generic_Encrypt(s.session_id(), clear_buffer_, kBufferSize, iv_,
                                  OEMCrypto_AES_CBC_128_NO_PADDING, encrypted);
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);
  ASSERT_EQ(0, memcmp(encrypted, expected_encrypted, kBufferSize));

  sleep(kLongSleep);  // Should be expired key.

  memset(encrypted, 0, kBufferSize);
  sts = OEMCrypto_Generic_Encrypt(s.session_id(), clear_buffer_, kBufferSize, iv_,
                                  OEMCrypto_AES_CBC_128_NO_PADDING, encrypted);
  ASSERT_NE(OEMCrypto_SUCCESS, sts);
  ASSERT_NE(0, memcmp(encrypted, expected_encrypted, kBufferSize));
  s.close();
  testTearDown();
}

TEST_F(DISABLED_GenericDRMTest, KeyDurationDecrypt) {
  OEMCryptoResult sts;
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();
  s.GenerateDerivedKeys();
  MakeFourKeys(&s);
  message_data_.keys[0].control.duration = htonl(kDuration);
  message_data_.keys[1].control.duration = htonl(kDuration);
  message_data_.keys[2].control.duration = htonl(kDuration);
  message_data_.keys[3].control.duration = htonl(kDuration);
  LoadFourKeys(&s);

  unsigned int key_index = 1;
  uint8_t encrypted[kBufferSize];
  EncryptBuffer(key_index, clear_buffer_, encrypted);
  sts = OEMCrypto_SelectKey(s.session_id(), message_data_.keys[key_index].key_id,
                            kTestKeyIdLength);
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);

  uint8_t resultant[kBufferSize];
  sleep(kShortSleep);  //  Should still be valid key.

  memset(resultant, 0, kBufferSize);
  sts = OEMCrypto_Generic_Decrypt(s.session_id(), encrypted, kBufferSize, iv_,
                                  OEMCrypto_AES_CBC_128_NO_PADDING, resultant);
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);
  ASSERT_EQ(0, memcmp(clear_buffer_, resultant, kBufferSize));

  sleep(kLongSleep);  // Should be expired key.

  memset(resultant, 0, kBufferSize);
  sts = OEMCrypto_Generic_Decrypt(s.session_id(), encrypted, kBufferSize, iv_,
                                  OEMCrypto_AES_CBC_128_NO_PADDING, resultant);
  ASSERT_NE(OEMCrypto_SUCCESS, sts);
  ASSERT_NE(0, memcmp(clear_buffer_, resultant, kBufferSize));
  s.close();
  testTearDown();
}

TEST_F(DISABLED_GenericDRMTest, KeyDurationSign) {
  OEMCryptoResult sts;
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();
  s.GenerateDerivedKeys();
  MakeFourKeys(&s);

  message_data_.keys[0].control.duration = htonl(kDuration);
  message_data_.keys[1].control.duration = htonl(kDuration);
  message_data_.keys[2].control.duration = htonl(kDuration);
  message_data_.keys[3].control.duration = htonl(kDuration);

  LoadFourKeys(&s);

  unsigned int key_index = 2;
  uint8_t expected_signature[SHA256_DIGEST_LENGTH];
  uint8_t signature[SHA256_DIGEST_LENGTH];
  size_t signature_length = SHA256_DIGEST_LENGTH;
  SignBuffer(key_index, clear_buffer_, expected_signature);

  sts = OEMCrypto_SelectKey(s.session_id(), message_data_.keys[key_index].key_id,
                            kTestKeyIdLength);
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);

  sleep(kShortSleep);  //  Should still be valid key.

  memset(signature, 0, SHA256_DIGEST_LENGTH);
  sts = OEMCrypto_Generic_Sign(s.session_id(), clear_buffer_, kBufferSize,
                               OEMCrypto_HMAC_SHA256,signature,
                               &signature_length);
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);
  ASSERT_EQ(0, memcmp(signature, expected_signature, SHA256_DIGEST_LENGTH));

  sleep(kLongSleep);  // Should be expired key.

  memset(signature, 0, SHA256_DIGEST_LENGTH);
  sts = OEMCrypto_Generic_Sign(s.session_id(), clear_buffer_, kBufferSize,
                               OEMCrypto_HMAC_SHA256,signature,
                               &signature_length);
  ASSERT_NE(OEMCrypto_SUCCESS, sts);
  ASSERT_NE(0, memcmp(signature, expected_signature, SHA256_DIGEST_LENGTH));

  s.close();
  testTearDown();
}

TEST_F(DISABLED_GenericDRMTest, KeyDurationVerify) {
  OEMCryptoResult sts;
  testSetUp();
  InstallKeybox(kDefaultKeybox, true);
  Session& s = createSession("ONE");
  s.open();
  s.GenerateDerivedKeys();
  MakeFourKeys(&s);
  message_data_.keys[0].control.duration = htonl(kDuration);
  message_data_.keys[1].control.duration = htonl(kDuration);
  message_data_.keys[2].control.duration = htonl(kDuration);
  message_data_.keys[3].control.duration = htonl(kDuration);
  LoadFourKeys(&s);

  unsigned int key_index = 3;
  uint8_t signature[SHA256_DIGEST_LENGTH];
  SignBuffer(key_index, clear_buffer_, signature);

  sts = OEMCrypto_SelectKey(s.session_id(), message_data_.keys[key_index].key_id,
                            kTestKeyIdLength);
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);

  sleep(kShortSleep);  //  Should still be valid key.

  sts = OEMCrypto_Generic_Verify(s.session_id(), clear_buffer_, kBufferSize,
                                 OEMCrypto_HMAC_SHA256,signature,
                                 SHA256_DIGEST_LENGTH);
  ASSERT_EQ(OEMCrypto_SUCCESS, sts);

  sleep(kLongSleep);  // Should be expired key.

  sts = OEMCrypto_Generic_Verify(s.session_id(), clear_buffer_, kBufferSize,
                                 OEMCrypto_HMAC_SHA256,signature,
                                 SHA256_DIGEST_LENGTH);
  ASSERT_NE(OEMCrypto_SUCCESS, sts);

  s.close();
  testTearDown();
}
}  // namespace wvoec
