/*******************************************************************************
 *
 * Copyright 2013 Google Inc. All Rights Reserved.
 *
 * mock implementation of OEMCrypto APIs
 *
 ******************************************************************************/

#include "oemcrypto_key_mock.h"

#include <cstring>

#include "log.h"
#include "wv_cdm_constants.h"

namespace wvoec_mock {

bool KeyControlBlock::Validate() {
  valid_ = false;
  if (0x6b63746c != verification_) {  // kctl.
    LOGE("KCB: BAD verification string: %08X (not %08X)", verification_,
         0x6b63746c);
    return false;
  }

  if (refresh_) {
    if (control_bits_ & kControlObserveDataPath) {
      LOGW("KCB: data_path_type set for refresh.");
    }
    if (control_bits_ & kControlObserveHDCP) {
      LOGW("KCB: HDCP setting set for refresh.");
    }
    if (control_bits_ & kControlObserveCGMS) {
      LOGW("KCB: CGMS setting set for refresh.");
    }
  }
  valid_ = true;
  return valid_;
}

// This extracts 4 bytes in network byte order to a 32 bit integer in
// host byte order.
uint32_t KeyControlBlock::ExtractField(const std::vector<uint8_t>& str, int idx) {
  int bidx = idx * 4;
  uint32_t t = static_cast<unsigned char>(str[bidx]) << 24;
  t |= static_cast<unsigned char>(str[bidx + 1]) << 16;
  t |= static_cast<unsigned char>(str[bidx + 2]) << 8;
  t |= static_cast<unsigned char>(str[bidx + 3]);
  return t;
}

bool KeyControlBlock::SetFromString(const std::vector<uint8_t>& key_control_string) {
  if (key_control_string.size() < wvcdm::KEY_CONTROL_SIZE) {
    LOGE("KCB: BAD Size: %d (not %d)",key_control_string.size(),
         wvcdm::KEY_CONTROL_SIZE);
    return false;
  }

  verification_ = ExtractField(key_control_string, 0);
  duration_     = ExtractField(key_control_string, 1);
  nonce_        = ExtractField(key_control_string, 2);
  control_bits_ = ExtractField(key_control_string, 3);

  return Validate();
}

Key::Key(KeyType ktype, const std::vector<uint8_t>& key_string,
         const KeyControlBlock& control) :
  valid_(true), type_(ktype),
  value_(key_string), has_control_(true),
  control_(control) {
}

bool Key::setValue(const char* key_string, size_t key_string_length) {
  valid_ = false;
  if (!key_string || key_string_length == 0) {
    return false;
  }

  value_.assign(key_string, key_string + key_string_length);

  if (isValidType() && has_control_) {
    valid_ = true;
  }
  return valid_;
}

bool Key::setType(KeyType ktype) {
  valid_ = false;
  type_ = ktype;
  if (value_.empty()) {
    return false;
  }

  if (isValidType() && has_control_) {
    valid_ = true;
  }
  return valid_;
}

bool Key::setControl(const KeyControlBlock& control) {
  valid_ = false;
  if (!control.valid()) {
    return false;
  }

  control_ = control;
  has_control_ = true;

  if (isValidType() && !value_.empty()) {
    valid_ = true;
  }
  return valid_;
}

bool Key::UpdateDuration(const KeyControlBlock& control) {
  valid_ = false;
  if (!control.valid() || !has_control_) {
    LOGE("UpdateDuration: control block not valid.");
    return false;
  }

  control_.set_duration(control.duration());

  if (isValidType() && !value_.empty()) {
    valid_ = true;
  } else {
    LOGE("UpdateDuration: value or type bad.");
  }
  return valid_;
}

}; // namespace wvoec_eng
