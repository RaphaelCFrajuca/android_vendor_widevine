//
// Copyright 2013 Google Inc. All Rights Reserved.
//

//#define LOG_NDEBUG 0
#define LOG_TAG "WVCdm"
#include <utils/Log.h>

#include "WVCDMSingleton.h"

#include "utils/Mutex.h"

namespace wvdrm {

using wvcdm::WvContentDecryptionModule;
using android::Mutex;

Mutex cdmLock;
WvContentDecryptionModule* cdm = NULL;

WvContentDecryptionModule* getCDM() {
  Mutex::Autolock lock(cdmLock);

  if (cdm == NULL) {
    ALOGD("Instantiating CDM.");
    cdm = new WvContentDecryptionModule();
  }

  return cdm;
}

} // namespace wvdrm
