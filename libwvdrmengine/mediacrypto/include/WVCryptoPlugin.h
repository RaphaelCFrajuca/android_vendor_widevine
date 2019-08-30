//
// Copyright 2013 Google Inc. All Rights Reserved.
//

#ifndef WV_CRYPTO_PLUGIN_H_
#define WV_CRYPTO_PLUGIN_H_

#include <stdint.h>

#include "media/hardware/CryptoAPI.h"
#include "media/stagefright/foundation/ABase.h"
#include "media/stagefright/foundation/AString.h"
#include "wv_content_decryption_module.h"

namespace wvdrm {

class WVCryptoPlugin : public android::CryptoPlugin {
 public:
  WVCryptoPlugin(const void* data, size_t size,
                 wvcdm::WvContentDecryptionModule* cdm);
  virtual ~WVCryptoPlugin() {}

  virtual bool requiresSecureDecoderComponent(const char* mime) const;

  virtual ssize_t decrypt(bool secure, const uint8_t key[16],
                          const uint8_t iv[16], Mode mode, const void* srcPtr,
                          const SubSample* subSamples, size_t numSubSamples,
                          void* dstPtr, android::AString* errorDetailMsg);

 private:
  DISALLOW_EVIL_CONSTRUCTORS(WVCryptoPlugin);

  wvcdm::WvContentDecryptionModule* const mCDM;

  bool mTestMode;
  const wvcdm::CdmSessionId mSessionId;

  wvcdm::CdmSessionId configureTestMode(const void* data, size_t size);
  static void incrementIV(uint64_t increaseBy, std::vector<uint8_t>* ivPtr);
};

} // namespace wvdrm

#endif // WV_CRYPTO_PLUGIN_H_
