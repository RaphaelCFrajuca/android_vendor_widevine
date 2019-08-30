/*******************************************************************************
 *
 * Copyright 2013 Google Inc. All Rights Reserved.
 *
 * mock implementation of OEMCrypto APIs
 *
 ******************************************************************************/

#include "oemcrypto_keybox_mock.h"
#include <arpa/inet.h>  // TODO(fredgc): Add ntoh to wv_cdm_utilities.h
#include <string>
#include <cstring>
#include <sys/types.h>
#include "log.h"
#include "wvcrc32.h"
#include "wv_keybox.h"

namespace wvoec_mock {

const WidevineKeybox kDefaultKeybox = {
  // Sample keybox used for test vectors
  {
    // deviceID
    0x54, 0x65, 0x73, 0x74, 0x4b, 0x65, 0x79, 0x30, // TestKey01
    0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
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

WvKeybox::WvKeybox() : valid_(false) {
  Prepare();
}

bool WvKeybox::Prepare() {
  InstallKeybox(reinterpret_cast<const uint8_t*>(&kDefaultKeybox),
                sizeof(kDefaultKeybox));
  valid_ = true;
  return valid_;
}

KeyboxError WvKeybox::Validate() {
  if (!valid_) {
    LOGE("[KEYBOX NOT LOADED]");
    return OTHER_ERROR;
  }
  if (strncmp(reinterpret_cast<char*>(magic_), "kbox", 4) != 0) {
    LOGE("[KEYBOX HAS BAD MAGIC]");
    return BAD_MAGIC;
  }
  uint32_t crc_computed;
  uint32_t* crc_stored = (uint32_t*)crc_;
  WidevineKeybox keybox;
  memset(&keybox, 0, sizeof(keybox));
  memcpy(keybox.device_id_, &device_id_[0], device_id_.size());
  memcpy(keybox.device_key_, &device_key_.value()[0], sizeof(keybox.device_key_));
  memcpy(keybox.data_, key_data_, sizeof(keybox.data_));
  memcpy(keybox.magic_, magic_, sizeof(keybox.magic_));

  crc_computed = ntohl(wvcrc32(reinterpret_cast<uint8_t*>(&keybox),
                               sizeof(keybox) - 4)); // Don't include last 4 bytes.
  if (crc_computed != *crc_stored) {
    LOGE("[KEYBOX CRC problem: computed = %08x,  stored = %08x]\n",
         crc_computed, *crc_stored);
    return BAD_CRC;
  }
  return NO_ERROR;
}

bool WvKeybox::InstallKeybox(const uint8_t* buffer, size_t keyBoxLength) {
  if (keyBoxLength != 128) {
    return false;
  }

  const WidevineKeybox* keybox
    = reinterpret_cast<const WidevineKeybox*>(buffer);
  device_id_.assign(keybox->device_id_,
                    keybox->device_id_ + sizeof(keybox->device_id_));
  device_key_.setValue(reinterpret_cast<const char*>(keybox->device_key_),
                       sizeof(keybox->device_key_));
  device_key_.setType(KEYTYPE_DEVICE);
  memcpy(key_data_, keybox->data_, sizeof(keybox->data_));
  memcpy(magic_, keybox->magic_, sizeof(keybox->magic_));
  memcpy(crc_, keybox->crc_, sizeof(keybox->crc_));
  return true;
}

}; // namespace wvoec_eng
