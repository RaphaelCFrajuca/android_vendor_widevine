//
// Copyright 2013 Google Inc. All Rights Reserved.
//

#include "WVCreatePluginFactories.h"

#include "WVCryptoFactory.h"
#include "WVDrmFactory.h"

extern "C" {

android::DrmFactory* createDrmFactory() {
  return new wvdrm::WVDrmFactory();
}

android::CryptoFactory* createCryptoFactory() {
  return new wvdrm::WVCryptoFactory();
}

} // extern "C"
