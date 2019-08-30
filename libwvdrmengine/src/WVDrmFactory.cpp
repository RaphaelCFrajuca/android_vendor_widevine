//
// Copyright 2013 Google Inc. All Rights Reserved.
//

//#define LOG_NDEBUG 0
#define LOG_TAG "WVCdm"
#include <utils/Log.h>

#include "WVDrmFactory.h"

#include "utils/Errors.h"
#include "WVCDMSingleton.h"
#include "WVDrmPlugin.h"
#include "WVUUID.h"

namespace wvdrm {

using namespace android;

WVGenericCryptoInterface WVDrmFactory::sOemCryptoInterface;

bool WVDrmFactory::isCryptoSchemeSupported(const uint8_t uuid[16]) {
  return isWidevineUUID(uuid);
}

bool WVDrmFactory::isContentTypeSupported(const String8 &mimeType) {
  // For now, only ISO-BMFF is supported, which has MIME-type video/mp4
  return mimeType == "video/mp4";
}

status_t WVDrmFactory::createDrmPlugin(const uint8_t uuid[16],
                                          DrmPlugin** plugin) {
  if (!isCryptoSchemeSupported(uuid)) {
    *plugin = NULL;
    return BAD_VALUE;
  }

  *plugin = new WVDrmPlugin(getCDM(), &sOemCryptoInterface);

  return OK;
}

} // namespace wvdrm
