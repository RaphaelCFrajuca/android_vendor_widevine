//
// Copyright 2013 Google Inc. All Rights Reserved.
//

#ifndef WV_CREATE_PLUGIN_FACTORIES_H_
#define WV_CREATE_PLUGIN_FACTORIES_H_

#include "media/drm/DrmAPI.h"
#include "media/hardware/CryptoAPI.h"

extern "C" {
  android::DrmFactory* createDrmFactory();
  android::CryptoFactory* createCryptoFactory();
}

#endif // WV_CREATE_PLUGIN_FACTORIES_H_
