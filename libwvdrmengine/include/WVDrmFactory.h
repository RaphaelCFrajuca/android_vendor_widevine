//
// Copyright 2013 Google Inc. All Rights Reserved.
//

#ifndef WV_DRM_FACTORY_H_
#define WV_DRM_FACTORY_H_

#include "media/drm/DrmAPI.h"
#include "media/stagefright/foundation/ABase.h"
#include "utils/Errors.h"
#include "WVGenericCryptoInterface.h"

namespace wvdrm {

class WVDrmFactory : public android::DrmFactory {
 public:
  WVDrmFactory() {};
  virtual ~WVDrmFactory() {};

  virtual bool isCryptoSchemeSupported(const uint8_t uuid[16]);

  virtual bool isContentTypeSupported(const android::String8 &mimeType);

  virtual android::status_t createDrmPlugin(const uint8_t uuid[16],
                                            android::DrmPlugin** plugin);

 private:
  DISALLOW_EVIL_CONSTRUCTORS(WVDrmFactory);

  static WVGenericCryptoInterface sOemCryptoInterface;
};

} // namespace wvdrm

#endif // WV_DRM_FACTORY_H_
