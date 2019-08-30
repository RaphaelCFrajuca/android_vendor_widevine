/*******************************************************************************
 *
 * Copyright 2013 Google Inc. All Rights Reserved.
 *
 * mock implementation of OEMCrypto APIs
 *
 ******************************************************************************/

#ifndef OEMCRYPTO_KEYBOX_MOCK_H_
#define OEMCRYPTO_KEYBOX_MOCK_H_

#include "oemcrypto_key_mock.h"

namespace wvoec_mock {

const int DEVICE_KEY_LENGTH = 16;
typedef uint8_t WvKeyboxKey[DEVICE_KEY_LENGTH];

const int KEY_DATA_LENGTH = 72;
typedef uint8_t WvKeyboxKeyData[KEY_DATA_LENGTH];

enum KeyboxError { NO_ERROR, BAD_CRC, BAD_MAGIC, OTHER_ERROR };

// Widevine keybox
class WvKeybox {
 public:
  WvKeybox();
  ~WvKeybox() {}

  KeyboxError Validate();
  const std::vector<uint8_t>& device_id() { return device_id_; }
  Key& device_key() { return device_key_; }
  const WvKeyboxKeyData& key_data() { return key_data_; }
  size_t key_data_length() { return KEY_DATA_LENGTH; }
  bool InstallKeybox(const uint8_t* keybox, size_t keyBoxLength);

 private:

  bool Prepare();

  bool valid_;
  std::vector<uint8_t> device_id_;
  Key device_key_;
  WvKeyboxKeyData key_data_;
  uint8_t magic_[4];
  uint8_t crc_[4];
};

};   // namespace wvoec_eng
#endif
