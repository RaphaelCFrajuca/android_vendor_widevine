//
// Copyright 2013 Google Inc. All Rights Reserved.
//

#ifndef WV_ERRORS_H_
#define WV_ERRORS_H_

#include "media/stagefright/MediaErrors.h"

namespace wvdrm {

using android::ERROR_DRM_VENDOR_MIN;
using android::ERROR_DRM_VENDOR_MAX;

enum {
  kErrorIncorrectBufferSize     = ERROR_DRM_VENDOR_MIN,
  kErrorCDMGeneric              = ERROR_DRM_VENDOR_MIN + 1,
  kErrorUnsupportedCrypto       = ERROR_DRM_VENDOR_MIN + 2,
  kErrorExpectedUnencrypted     = ERROR_DRM_VENDOR_MIN + 3,
  kErrorSessionIsOpen           = ERROR_DRM_VENDOR_MIN + 4,
  kErrorWVDrmMaxErrorUsed       = ERROR_DRM_VENDOR_MIN + 4,

  // Used by crypto test mode
  kErrorTestMode                = ERROR_DRM_VENDOR_MAX,
};

_STLP_STATIC_ASSERT(static_cast<uint32_t>(kErrorWVDrmMaxErrorUsed) <=
    static_cast<uint32_t>(ERROR_DRM_VENDOR_MAX));

} // namespace wvdrm

#endif // WV_ERRORS_H_
