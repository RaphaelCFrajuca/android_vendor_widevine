// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <vector>
#include <map>
#include <sstream>

#include "base/at_exit.h"
#include "base/basictypes.h"
#include "base/bind.h"
#include "base/message_loop.h"
#include "base/sys_byteorder.h"
#include "crypto/encryptor.h"
#include "crypto/hmac.h"
#include "crypto/symmetric_key.h"
#include "license_protocol.pb.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "eureka/widevine_cdm/oemcrypto/client/oemcrypto_client.h"
#include "eureka/widevine_cdm/oemcrypto/mock/src/cmac.h"
#include "eureka/widevine_cdm/oemcrypto/mock/src/oemcrypto_keybox_mock.h"
#include "wv_cdm_types.h"
#include "wv_content_decryption_module.h"

namespace {

namespace wv_license_protocol = video_widevine_server::sdk;

using wv_license_protocol::License;
using wv_license_protocol::LicenseIdentification;
using wv_license_protocol::LicenseRequest;
using wv_license_protocol::SessionState;
using wv_license_protocol::SignedMessage;

enum PolicyType {
  kDefault = 0,
  kNoPlay,
  kShortDuration
};

struct PolicyItem {
  PolicyType type;
  bool can_play;
  bool can_renew;
  int duration_seconds;
  int renewal_delay_seconds;
  int renewal_retry_interval_seconds;
};

struct PolicyItem PolicyItems[] = {
  {
    kDefault,
    true,
    true,
    1000,
    100,
    0
  },
  {
    kShortDuration,
    true,
    true,
    12,
    2,
    2
  },
  {
    kNoPlay,
    false,
    false,
    0,
    0,
    0
  }
};

// TODO(jfore): Move this into the test class.
/*const*/ char kTestSigningKey[] = {
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
};
const int kTestSigningKeySize = arraysize(kTestSigningKey);

const char* kEncryptionKeyLabel = "ENCRYPTION";
const uint32_t kEncryptionKeySizeBits = 128;
const char* kSigningKeyLabel = "AUTHENTICATION";
const uint32_t kSigningKeySizeBits = 256;

// This is a container to hold the info for an encrypted frame.
struct WvCdmEncryptedFrameInfo {
  char plain_text[32];
  int plain_text_size;
  uint8_t key_id[32];
  int key_id_size;
  uint8_t content_key[32];
  int content_key_size;
  uint8_t encrypted_data[64];
  int encrypted_data_size;
  PolicyType policy_type;
};

const WvCdmEncryptedFrameInfo kWvCdmEncryptedFrames[] = {
  {
    "Original data.", 14,
    { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
      0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35
    }, 16,
    { 0xeb, 0xdd, 0x62, 0xf1, 0x68, 0x14, 0xd2, 0x7b,
      0x68, 0xef, 0x12, 0x2a, 0xfc, 0xe4, 0xae, 0x3c
    }, 16,
    { 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0x82, 0x54, 0xab, 0x89, 0xa2, 0x75, 0xcd,
      0x85, 0x83, 0x61, 0x3f, 0xfe, 0x13, 0x58
    }, 23,
    kShortDuration
  },
  {
    "Original data.", 14,
    { 0x08, 0x01, 0x12, 0x10, 0x6f, 0x13, 0x33, 0xe7,
      0x6e, 0x59, 0x5e, 0xb5, 0x8c, 0x04, 0x30, 0x72,
      0xcb, 0xb2, 0x50, 0x68
    }, 20,
    { 0xeb, 0xdd, 0x62, 0xf1, 0x68, 0x14, 0xd2, 0x7b,
      0x68, 0xef, 0x12, 0x2a, 0xfc, 0xe4, 0xae, 0x3c
    }, 16,
    { 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0x82, 0x54, 0xab, 0x89, 0xa2, 0x75, 0xcd,
      0x85, 0x83, 0x61, 0x3f, 0xfe, 0x13, 0x58
    }, 23,
    kShortDuration
  },
  {
    "Changed Original data.", 22,
    { 0x01, 0x02, 0x01, 0x02, 0x01, 0x02, 0x01, 0x02,
      0x01, 0x02, 0x01, 0x02, 0x01, 0x02, 0x01, 0x02
    }, 16,
    { 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
      0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23
    }, 16,
    { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x57, 0x66, 0xf4, 0x12, 0x1a, 0xed, 0xb5,
      0x79, 0x1c, 0x8e, 0x25, 0xd7, 0x17, 0xe7, 0x5e,
      0x16, 0xe3, 0x40, 0x08, 0x27, 0x11, 0xe9
    }, 31,
    kShortDuration
  },
  {
    "Original data.", 14,
    { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
      0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
    }, 16,
    { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
      0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40
    }, 16,
    { 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x9c, 0x71, 0x26, 0x57, 0x3e, 0x25, 0x37,
      0xf7, 0x31, 0x81, 0x19, 0x64, 0xce, 0xbc
    }, 23,
    kShortDuration
  },
  // For license renewal test. This has kNoPlay.
  {
    // Differnent key and key id.
    "Original data.", 14,
    { 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
      0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33
    }, 16,
    { 0xeb, 0xdd, 0x62, 0xf1, 0x68, 0x14, 0xd2, 0x7b,
      0x68, 0xef, 0x12, 0x2a, 0xfc, 0xe4, 0xae, 0x3c
    }, 16,
    { 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0x82, 0x54, 0xab, 0x89, 0xa2, 0x75, 0xcd,
      0x85, 0x83, 0x61, 0x3f, 0xfe, 0x13, 0x58
    }, 23,
    kNoPlay
  }
};

bool GetPolicy(PolicyType policy_type, License::Policy* policy) {
  DCHECK(policy);
  PolicyItem policy_item;
  switch (policy_type) {
    case kDefault:
      policy_item = PolicyItems[0];
      DCHECK_EQ(policy_item.type, kDefault);
      break;
    case kShortDuration:
      policy_item = PolicyItems[1];
      DCHECK_EQ(policy_item.type, kShortDuration);
      break;
    case kNoPlay:
      policy_item = PolicyItems[2];
      DCHECK_EQ(policy_item.type, kNoPlay);
      break;
    default:
      NOTREACHED();
      return false;
  }
  policy->set_can_play(policy_item.can_play);
  policy->set_can_renew(policy_item.can_renew);
  policy->set_license_duration_seconds(policy_item.duration_seconds);
  policy->set_renewal_delay_seconds(policy_item.renewal_delay_seconds);
  policy->set_renewal_retry_interval_seconds(
      policy_item.renewal_retry_interval_seconds);
  return true;
}

SessionState GetTestSessionState() {
  static const std::string kTestSessionId = "SomeSessionId";
  SessionState session_cache;
  session_cache.mutable_license_id()->set_session_id(kTestSessionId);
  session_cache.mutable_license_id()->set_version(0);
  session_cache.set_signing_key(kTestSigningKey, kTestSigningKeySize);
  return session_cache;
}

// Since "GetTime" is used in this test where some functions cannot reach
// Host instance, this will be used as a universal clock for this test.
double GetCurrentTestTime() {
  return base::Time::Now().ToDoubleT();
}

// This encrypts the content key using the device key in cdm/base/device_key.h.
std::string EncryptUsingKey(const std::string& input,
                            const std::string& iv,
                            const std::string& encryption_key) {
  //static const int kAesBlockSize = 16;
  crypto::Encryptor aes_ecryptor;
  scoped_ptr<crypto::SymmetricKey> device_key(
      crypto::SymmetricKey::Import(crypto::SymmetricKey::AES,
                                   encryption_key));
  if (!aes_ecryptor.Init(device_key.get(), crypto::Encryptor::CBC, iv))
    return "";

  std::string encrypted_data;
  if (!aes_ecryptor.Encrypt(input, &encrypted_data))
    return "";

  return encrypted_data;
}

// Takes the license and the session state and generates a SignedMessage. The
// return value is the serialized version of the SignedMessage object.
std::string GenerateSignedLicenseResponse(const License& license,
                                          const std::string& signing_key) {
  SignedMessage signed_message;
  bool success = license.SerializeToString(
      signed_message.mutable_msg());
  DCHECK(success);

  crypto::HMAC hmacer(crypto::HMAC::SHA256);
  if (!hmacer.Init(signing_key))
    return "";

  static const int kDigestSize = 32;
  uint8_t digest[kDigestSize] = { 0 };
  if (!hmacer.Sign(signed_message.msg(), digest, kDigestSize))
    return "";

  signed_message.set_signature(digest, kDigestSize);

  std::string signed_message_bytes;
  success = signed_message.SerializeToString(&signed_message_bytes);
  DCHECK(success);

  return signed_message_bytes;
}

// Note: We only use one session. So there aren't any list of sessions stored
// anywhere.
std::string GenerateNewSignedLicense(
    const LicenseRequest& license_request,
    const License::Policy& policies,
    const License::KeyContainer& content_key,
    const std::string& encryption_key,
    const std::string& signing_key) {
  DCHECK(license_request.content_id().has_cenc_id());
  SessionState session_cache = GetTestSessionState();
  DCHECK(session_cache.has_signing_key());

  session_cache.mutable_license_id()->set_request_id(
      license_request.content_id().webm_id().request_id());
  session_cache.mutable_license_id()->set_type(
      license_request.content_id().webm_id().license_type());

  License license;
  license.mutable_id()->CopyFrom(session_cache.license_id());
  license.mutable_policy()->CopyFrom(policies);
  license.set_license_start_time(GetCurrentTestTime());

  License::KeyContainer* renewal_signing_key = license.add_key();
  renewal_signing_key->set_key(session_cache.signing_key());
  renewal_signing_key->set_type(License::KeyContainer::SIGNING);

  license.add_key()->CopyFrom(content_key);
  for (int i = 0; i < license.key_size(); ++i) {
    license.mutable_key(i)->set_iv("0123456789012345");
    license.mutable_key(i)->set_key(
        EncryptUsingKey(license.key(i).key(),
                        license.key(i).iv(),
                        encryption_key));
    if (license.key(i).key().empty())
      return "";
  }

  return GenerateSignedLicenseResponse(license, signing_key);
}

bool GetContentKeyFromKeyId(const std::string& key_id,
                         std::string* content_key) {
  DCHECK(content_key);
  for (unsigned int i = 0; i < arraysize(kWvCdmEncryptedFrames); ++i) {
    const WvCdmEncryptedFrameInfo& frame = kWvCdmEncryptedFrames[i];
    if (frame.key_id_size != static_cast<int>(key_id.size()))
        continue;
    if (!memcmp(frame.key_id, key_id.data(), frame.key_id_size)) {
      content_key->assign(frame.content_key,
                          frame.content_key + frame.content_key_size);
      return true;
    }
  }
  return false;
}

std::string DeriveKey(const std::string& key,
                      const std::string& purpose,
                      const std::string& context,
                      const uint32_t size_bits) {
  if (key.size() != 16)
    return "";

  // We only handle even multiples of 16 bytes (128 bits) right now.
  if ((size_bits % 128) || (size_bits > (128 * 255))) {
    return "";
  }

  std::string result;

  const EVP_CIPHER *cipher = EVP_aes_128_cbc();
  CMAC_CTX* cmac_ctx = CMAC_CTX_new();

  size_t reslen;
  unsigned char res[128];
  unsigned char counter;
  for (counter = 1; counter <= (size_bits / 128); counter++) {
    if (!CMAC_Init(cmac_ctx, key.data(), key.size(), cipher, 0))
      break;

    std::string message;
    message.append(1, counter);
    message.append(purpose);
    message.append(1, '\0');
    message.append(context);
    uint32_t size_l = htonl(size_bits);
    message.append(reinterpret_cast<char*>(&size_l), sizeof(size_l));
    if (!CMAC_Update(cmac_ctx, message.data(), message.size()))
      break;

    if (!CMAC_Final(cmac_ctx, res, &reslen))
      break;

    result.append((const char*)res, reslen);
  }

  CMAC_CTX_free(cmac_ctx);

  if (counter <= (size_bits / 128))
    return "";

  return result;
}

bool VerifyTestSignature(const std::string& message,
                         const std::string& signature,
                         const std::string& key) {
  crypto::HMAC hmacer(crypto::HMAC::SHA256);
  if (!hmacer.Init(key))
    return false;

  if (!hmacer.Verify(message, signature))
    return false;

  return true;
}

std::string GenerateNewLicenseResponse(const LicenseRequest& license_request,
                                       const PolicyType& policy_type) {
  if (!license_request.content_id().has_cenc_id())
    return "";

  std::string content_key_id = license_request.content_id().cenc_id().pssh(0);

  std::string content_key;
  if (!GetContentKeyFromKeyId(content_key_id,
                              &content_key)) {
    return "";
  }

  if (content_key_id.size() > 16)
    content_key_id.resize(16);

  License::Policy policies;
  if (!GetPolicy(policy_type, &policies))
    return "";

  std::string context;
  if (!license_request.SerializeToString(&context))
    return "";

  wvoec_mock::WvKeybox keybox;

  // TODO(): Fix this to use a constant for key length.
  std::string widevine_device_key(keybox.device_key().value());
  std::string encryption_key = DeriveKey(widevine_device_key,
                                         std::string(kEncryptionKeyLabel),
                                         context,
                                         kEncryptionKeySizeBits);
  std::string signing_key = DeriveKey(widevine_device_key,
                                      std::string(kSigningKeyLabel),
                                      context,
                                      kSigningKeySizeBits);

  memcpy(kTestSigningKey, &signing_key[0], 32);

  License::KeyContainer key_container;
  key_container.set_id(content_key_id);
  key_container.set_key(content_key);
  key_container.set_type(License::KeyContainer::CONTENT);
  return GenerateNewSignedLicense(license_request,
                                  policies,
                                  key_container,
                                  encryption_key,
                                  signing_key);
}

std::string GenerateLicenseRenewalResponse(
    const SignedMessage& signed_message,
    const PolicyType& policy_type) {
  SessionState session_cache = GetTestSessionState();

  LicenseRequest license_request;
  if (!license_request.ParseFromString(signed_message.msg()))
    return "";

  std::string session_id = license_request.content_id().license().
      license_id().session_id();
  if (session_id.compare(session_cache.license_id().session_id()))
    return "";

  if (!VerifyTestSignature(signed_message.msg(),
                           signed_message.signature(),
                           session_cache.signing_key())) {
    return "";
  }
  session_cache.mutable_license_id()->set_version(
      session_cache.license_id().version() + 1);

  License license;
  license.mutable_id()->CopyFrom(session_cache.license_id());

  // Always get Policy object with kDefault for renewal.
  License::Policy policy;
  GetPolicy(policy_type, &policy);
  license.mutable_policy()->Swap(&policy);
  license.set_license_start_time(GetCurrentTestTime());

  return GenerateSignedLicenseResponse(license, session_cache.signing_key());
}

std::string GenerateLicenseResponse(const std::string& signed_request,
                                    const PolicyType& policy) {
  SignedMessage signed_message;
  if (!signed_message.ParseFromString(signed_request))
    return "";

  LicenseRequest license_request;
  if (!license_request.ParseFromString(signed_message.msg()))
    return "";

  if (license_request.type() == LicenseRequest::NEW) {
    return GenerateNewLicenseResponse(license_request, policy);
  } else if (license_request.type() == LicenseRequest::RENEWAL) {
    return GenerateLicenseRenewalResponse(signed_message, policy);
  }

  return "";
}

struct WvCdmEncryptedData {
  char plain_text[32];
  int plain_text_size;
  uint8_t key_id[32];
  int key_id_size;
  uint8_t content_key[32];
  int content_key_size;
  uint8_t encrypted_data[64];
  int encrypted_data_size;
  const char* license_response;
  int license_response_size;
};

// Container used to pass data from GenerateLicenseRequest to Decrypt.
// TODO(rkuroiwa): This class was made before KeyMessage existed; this
// should be removed.
class LicenseRequestParameter {
 public:
  explicit LicenseRequestParameter(const WvCdmEncryptedData& frame)
      : init_data(new uint8_t[frame.key_id_size]),
        init_data_size(frame.key_id_size),
        session_id(NULL),
        session_id_size(0),
        key_request(NULL),
        key_request_size(0),
        default_url(NULL),
        default_url_size(0) {
    memcpy(init_data.get(), frame.key_id, frame.key_id_size);
  }

  ~LicenseRequestParameter() {
  }

  scoped_array<uint8_t> init_data;
  int init_data_size;
  scoped_array<char> session_id;
  int session_id_size;
  scoped_array<uint8_t> key_request;
  int key_request_size;
  scoped_array<char> default_url;
  int default_url_size;

 private:
  DISALLOW_COPY_AND_ASSIGN(LicenseRequestParameter);
};

// |encrypted_data| is encrypted from |plain_text| using |key|. |key_id| is
// used to distinguish |key|.
struct WebmEncryptedData {
  uint8 plain_text[32];
  int plain_text_size;
  uint8 key_id[32];
  int key_id_size;
  uint8 key[32];
  int key_size;
  uint8 encrypted_data[64];
  int encrypted_data_size;
};

// Frames 0 & 1 are encrypted with the same key. Frame 2 is encrypted with a
// different key. Frame 3 is unencrypted.
const WebmEncryptedData kWebmEncryptedFrames[] = {
  {
    // plaintext
    "Original data.", 14,
    // key_id
    { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      0x10, 0x11, 0x12, 0x13
      }, 20,
    // key
    { 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
      0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23
      }, 16,
    // encrypted_data
    { 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xf0, 0xd1, 0x12, 0xd5, 0x24, 0x81, 0x96,
      0x55, 0x1b, 0x68, 0x9f, 0x38, 0x91, 0x85
      }, 23
  },
  {
    // plaintext
    "Changed Original data.", 22,
    // key_id
    { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      0x10, 0x11, 0x12, 0x13
      }, 20,
    // key
    { 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
      0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23
      }, 16,
    // encrypted_data
    { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x57, 0x66, 0xf4, 0x12, 0x1a, 0xed, 0xb5,
      0x79, 0x1c, 0x8e, 0x25, 0xd7, 0x17, 0xe7, 0x5e,
      0x16, 0xe3, 0x40, 0x08, 0x27, 0x11, 0xe9
      }, 31
  },
  {
    // plaintext
    "Original data.", 14,
    // key_id
    { 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
      0x2c, 0x2d, 0x2e, 0x2f, 0x30
      }, 13,
    // key
    { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
      0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40
      }, 16,
    // encrypted_data
    { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x01, 0x9c, 0x71, 0x26, 0x57, 0x3e, 0x25, 0x37,
      0xf7, 0x31, 0x81, 0x19, 0x64, 0xce, 0xbc
      }, 23
  },
  {
    // plaintext
    "Changed Original data.", 22,
    // key_id
    { 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
      0x2c, 0x2d, 0x2e, 0x2f, 0x30
      }, 13,
    // key
    { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
      0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40
      }, 16,
    // encrypted_data
    { 0x00, 0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x64,
      0x20, 0x4f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x61,
      0x6c, 0x20, 0x64, 0x61, 0x74, 0x61, 0x2e
      }, 23
  }
};

static const uint8 kWebmWrongSizedKey[] = { 0x20, 0x20 };

static const char kClearKeySystem[] = "org.w3.clearkey";
static const char *kWidevineKeySystem = "com.widevine.alpha";
static const char kKeyType[] = "any";

// All three ContentIdentification are supported but cenc_id only supports
// one key for now.
// Using key_id kCencTestRequest will return the content_key kCencTestRequest
//
static const char kCencTestRequest[] = "0123456789ABCDEF";
static const char kCencTestContentKey[] = {
    0x16, 0x23, 0xa3, 0x16, 0x67, 0x6d, 0xb7, 0x70,
    0xfe, 0x78, 0xf6, 0x58, 0x42, 0xb8, 0x16, 0x3c
};

// System Id of the Widevine DRM system for identification in pssh
static const uint8 kWidevineSystemId[] = {
    0xED, 0xEF, 0x8B, 0xA9, 0x79, 0xD6, 0x4A, 0xCE,
    0xA3, 0xC8, 0x27, 0xDC, 0xD5, 0x1D, 0x21, 0xED,
};

static std::string EncodeInt32(int i) {
  std::string s;
  s.resize(sizeof(int));
  memcpy(&*s.begin(), &i, sizeof(int));
  return s;
}

// Generate PSSH blob from init data
static std::string GeneratePSSHBlob(const uint8* init_data,
                             int init_data_length) {
  std::string output;

  // 4 byte size of the PSSH atom, inclusive
  int size = 4 + 4 + 4 + sizeof(kWidevineSystemId) + 4 + init_data_length;
  output.append(EncodeInt32(base::HostToNet32(size)));

  // "pssh"
  output.append("pssh");

  // 4 byte flags, value 0
  int flag = 0;
  output.append(EncodeInt32(base::HostToNet32(flag)));

  // 16 byte system id
  output.append(reinterpret_cast<const char*>(kWidevineSystemId),
                sizeof(kWidevineSystemId));

  // 4 byte size of PSSH data, exclusive
  output.append(EncodeInt32(base::HostToNet32(init_data_length)));

  // pssh data
  output.append(reinterpret_cast<const char*>(init_data),
                init_data_length);

  return output;
}

};  // anonymous

namespace wvcdm {

class WvCdmDecryptorTest : public testing::Test {

 public:
  WvCdmDecryptorTest() {}

  ~WvCdmDecryptorTest() {}

 protected:
  void GenerateKeyRequest(const uint8* key_id, int key_id_size,
                          std::string& message_buffer) {
    std::string init_data = GeneratePSSHBlob(key_id, key_id_size);
    wvcdm::CdmResponseType res = decryptor_.GenerateKeyRequest(
        kWidevineKeySystem, init_data, &message_buffer, &session_id_string_);
    EXPECT_TRUE(res == wvcdm::KEY_MESSAGE);
  }

  void PrepareForRenewalRequest(int i) {
  }

  void GetRenewalMessage(std::string& message_buffer) {
  }

  void GetFailedRenewalMessage(std::string& message_buffer) {
  }

 public:
  void AddKeyAndExpectToSucceed(const uint8* key_id, int key_id_size,
                                const uint8* key, int key_size) {
    std::string cma_key((const char*)key, key_size);
    std::string init_data = GeneratePSSHBlob(key_id, key_id_size);
    wvcdm::CdmResponseType res = decryptor_.AddKey(
        kWidevineKeySystem, init_data, cma_key, session_id_string_);
    EXPECT_TRUE(res == wvcdm::KEY_ADDED);
  }

  void AddKeyAndExpectToFail(const uint8* key_id, int key_id_size,
                             const uint8* key, int key_size) {
    std::string cma_key((const char*)key, key_size);
    std::string init_data = GeneratePSSHBlob(key_id, key_id_size);
    wvcdm::CdmResponseType res = decryptor_.AddKey(
        kWidevineKeySystem, init_data, cma_key, session_id_string_);
    EXPECT_TRUE(res == wvcdm::KEY_ADDED);
  }
 protected:

  wvcdm::WvContentDecryptionModule decryptor_;
  std::string session_id_string_;
};

TEST_F(WvCdmDecryptorTest, RenewalTest) {
  std::string response;
  std::string message;
  const WvCdmEncryptedFrameInfo& frame = kWvCdmEncryptedFrames[3];
  License::Policy policies;
  DCHECK(GetPolicy(frame.policy_type, &policies));

  GenerateKeyRequest(frame.key_id, frame.key_id_size, message);
  response = GenerateLicenseResponse(message, kShortDuration);
  AddKeyAndExpectToSucceed(frame.key_id, frame.key_id_size,
                           reinterpret_cast<const uint8*>(response.data()),
                           response.size());
  MessageLoop::current()->RunUntilIdle();
  PrepareForRenewalRequest(1);
  sleep(policies.renewal_delay_seconds());
  MessageLoop::current()->RunUntilIdle();
  GetRenewalMessage(message);
  response = GenerateLicenseResponse(message, frame.policy_type);
  AddKeyAndExpectToSucceed(frame.key_id, frame.key_id_size,
                           reinterpret_cast<const uint8*>(response.data()),
                           response.size());
}

TEST_F(WvCdmDecryptorTest, MultiRenewalTest) {
  std::string response;
  std::string message;
  const WvCdmEncryptedFrameInfo& frame = kWvCdmEncryptedFrames[3];
  License::Policy policies;
  DCHECK(GetPolicy(frame.policy_type, &policies));

  GenerateKeyRequest(frame.key_id, frame.key_id_size, message);
  response = GenerateLicenseResponse(message, kShortDuration);
  AddKeyAndExpectToSucceed(frame.key_id, frame.key_id_size,
                           reinterpret_cast<const uint8*>(response.data()),
                           response.size());
  MessageLoop::current()->RunUntilIdle();
  PrepareForRenewalRequest(1);
  sleep(policies.renewal_delay_seconds());
  MessageLoop::current()->RunUntilIdle();
  GetRenewalMessage(message);
  response = GenerateLicenseResponse(message, frame.policy_type);
  AddKeyAndExpectToSucceed(frame.key_id, frame.key_id_size,
                           reinterpret_cast<const uint8*>(response.data()),
                           response.size());

  PrepareForRenewalRequest(2);
  sleep(policies.renewal_delay_seconds());
  MessageLoop::current()->RunUntilIdle();
  GetRenewalMessage(message);
}

TEST_F(WvCdmDecryptorTest, RenewalRetryTest_ExpectSuccess) {
  std::string response;
  std::string message;
  const WvCdmEncryptedFrameInfo& frame = kWvCdmEncryptedFrames[3];
  License::Policy policies;
  DCHECK(GetPolicy(frame.policy_type, &policies));

  GenerateKeyRequest(frame.key_id, frame.key_id_size, message);
  response = GenerateLicenseResponse(message, kShortDuration);
  AddKeyAndExpectToSucceed(frame.key_id, frame.key_id_size,
      reinterpret_cast<const uint8*>(response.data()),
      response.size());
  MessageLoop::current()->RunUntilIdle();

  int loop_seconds =
        policies.license_duration_seconds() - policies.renewal_delay_seconds();
    int loop_count = loop_seconds / policies.renewal_retry_interval_seconds();
    if (loop_seconds % policies.renewal_retry_interval_seconds())
      ++loop_count;
  for (int i = 1; i <= loop_count; ++i) {
    PrepareForRenewalRequest(i);
    sleep(policies.renewal_delay_seconds());
    MessageLoop::current()->RunUntilIdle();
    GetRenewalMessage(message);
  }

  response = GenerateLicenseResponse(message, frame.policy_type);
  AddKeyAndExpectToSucceed(frame.key_id, frame.key_id_size,
      reinterpret_cast<const uint8*>(response.data()),
      response.size());
}

TEST_F(WvCdmDecryptorTest, RenewalRetryTest_ExpectLicenseExpiration) {
  std::string response;
  std::string message;
  const WvCdmEncryptedFrameInfo& frame = kWvCdmEncryptedFrames[3];
  License::Policy policies;
  DCHECK(GetPolicy(frame.policy_type, &policies));

  GenerateKeyRequest(frame.key_id, frame.key_id_size, message);
  response = GenerateLicenseResponse(message, kShortDuration);
  AddKeyAndExpectToSucceed(frame.key_id, frame.key_id_size,
      reinterpret_cast<const uint8*>(response.data()),
      response.size());
  MessageLoop::current()->RunUntilIdle();

  int loop_seconds =
      policies.license_duration_seconds() - policies.renewal_delay_seconds();
  int loop_count = loop_seconds / policies.renewal_retry_interval_seconds() + 1;
  if (loop_seconds % policies.renewal_retry_interval_seconds())
    ++loop_count;

  for (int i = 1; i <= loop_count; ++i) {
    PrepareForRenewalRequest(i);
    sleep(i > 1 ?
        policies.renewal_retry_interval_seconds() :
        policies.renewal_delay_seconds());
    MessageLoop::current()->RunUntilIdle();
    if (i < loop_count)
    GetRenewalMessage(message);
  }
  GetFailedRenewalMessage(message);
}

}  // namespace wvcdm

// TODO(rkuroiwa): Find where to put this main function just for Widevine CDM
// unit tests.
int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  base::AtExitManager exit;
  MessageLoop ttr(MessageLoop::TYPE_IO);
  return RUN_ALL_TESTS();
}
