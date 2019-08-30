/*******************************************************************************
 *
 * Copyright 2013 Google Inc. All Rights Reserved.
 *
 * mock implementation of OEMCrypto APIs
 *
 ******************************************************************************/

#ifndef OEMCRYPTO_KEY_MOCK_H_
#define OEMCRYPTO_KEY_MOCK_H_

#include <stdint.h>
#include <string>
#include <vector>

namespace wvoec_mock {

enum KeyType {
  KEYTYPE_UNKNOWN,
  KEYTYPE_PREPROV,
  KEYTYPE_ROOT,
  KEYTYPE_DEVICE,
  KEYTYPE_CONTENT,
  KEYTYPE_CONTENT_AUDIO,
  KEYTYPE_CONTENT_VIDEO,
  KEYTYPE_MAX
};

const uint32_t kControlObserveDataPath = (1<<31);
const uint32_t kControlObserveHDCP     = (1<<30);
const uint32_t kControlObserveCGMS     = (1<<29);
const uint32_t kControlAllowEncrypt    = (1<<8);
const uint32_t kControlAllowDecrypt    = (1<<7);
const uint32_t kControlAllowSign       = (1<<6);
const uint32_t kControlAllowVerify     = (1<<5);
const uint32_t kControlDataPathSecure  = (1<<4);
const uint32_t kControlNonceEnabled    = (1<<3);
const uint32_t kControlHDCPRequired    = (1<<2);
const uint32_t kControlCGMSMask        = (0x03);
const uint32_t kControlCGMSCopyFreely  = (0x00);
const uint32_t kControlCGMSCopyOnce    = (0x02);
const uint32_t kControlCGMSCopyNever   = (0x03);

class KeyControlBlock {
 public:
  KeyControlBlock() : valid_(false) {}
  KeyControlBlock(bool refresh) : valid_(false), refresh_(refresh) {}
  ~KeyControlBlock() {}

  bool SetFromString(const std::vector<uint8_t>& key_control_string);
  bool Validate();
  void Invalidate() { valid_ = false; }

  bool valid() const { return valid_; }
  uint32_t duration() const { return duration_; }
  void set_duration(uint32_t duration) { duration_ = duration; }
  uint32_t nonce() const { return nonce_; }
  uint32_t control_bits() const { return control_bits_; }

 private:

  uint32_t ExtractField(const std::vector<uint8_t>& str, int idx);

  bool valid_;
  bool refresh_;
  uint32_t verification_;
  uint32_t duration_;
  uint32_t nonce_;
  uint32_t control_bits_;
};

// AES-128 crypto key
class Key {
 public:
  Key() : valid_(false), type_(KEYTYPE_UNKNOWN), has_control_(false) {}
  Key(const Key& key) : valid_(key.valid_), type_(key.type_),
    value_(key.value_),
    has_control_(key.has_control_),
    control_(key.control_) {}
  Key(KeyType type, const std::vector<uint8_t>& key_string,
      const KeyControlBlock& control);

  virtual ~Key() {};

  // Key is valid iff setValue(), setType(), and setControl() have been called
  bool setValue(const char* key_string, size_t key_string_length);
  bool setType(KeyType ktype);
  bool setControl(const KeyControlBlock& control);
  bool UpdateDuration(const KeyControlBlock& control);

  KeyType keyType() { return type_; }
  const std::vector<uint8_t>& value() const { return value_; }
  const KeyControlBlock& control() const { return control_; }

  bool isDeviceKey() { return (KEYTYPE_DEVICE == type_); }
  bool isRootKey() { return (KEYTYPE_ROOT == type_); }
  bool isPreprovKey() { return (KEYTYPE_PREPROV == type_); }
  bool isContentKey() {
    bool ctypes = (KEYTYPE_CONTENT == type_) ||
                  (KEYTYPE_CONTENT_AUDIO == type_) ||
                  (KEYTYPE_CONTENT_VIDEO == type_);
    return ctypes;
  }
  bool isValidType() {
    return ((KEYTYPE_UNKNOWN < type_) && (KEYTYPE_MAX > type_));
  }
  bool isValid() { return valid_; }

  void clear() { value_.clear(); valid_ = false; }

 private:
  bool valid_;
  KeyType type_;
  std::vector<uint8_t> value_;
  bool has_control_;
  KeyControlBlock control_;
};

};   // namespace wvoec_eng

#endif
