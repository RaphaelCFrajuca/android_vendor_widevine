//
// Copyright 2013 Google Inc. All Rights Reserved.
//

#ifndef WV_MAP_ERRORS_H_
#define WV_MAP_ERRORS_H_

#include "media/stagefright/MediaErrors.h"
#include "utils/Errors.h"
#include "wv_cdm_types.h"
#include "WVErrors.h"

namespace wvdrm {

static android::status_t mapCdmResponseType(wvcdm::CdmResponseType res) {
  switch (res) {
    case wvcdm::NO_ERROR:
    case wvcdm::KEY_ADDED:
    case wvcdm::KEY_MESSAGE:
    case wvcdm::KEY_CANCELED:
      // KEY_ADDED, KEY_MESSAGE, and KEY_CANCELLED are all alternative
      // success messages for certain CDM methods instead of NO_ERROR.
      return android::OK;
    case wvcdm::NEED_KEY:
      return android::ERROR_DRM_NO_LICENSE;
    case wvcdm::NEED_PROVISIONING:
      return android::ERROR_DRM_NOT_PROVISIONED;
    case wvcdm::DEVICE_REVOKED:
      return android::ERROR_DRM_DEVICE_REVOKED;
    case wvcdm::INSUFFICIENT_CRYPTO_RESOURCES:
      return android::ERROR_DRM_RESOURCE_BUSY;
    case wvcdm::KEY_ERROR:
      // KEY_ERROR is used by the CDM to mean just about any kind of error, not
      // just license errors, so it is mapped to the generic response.
      return kErrorCDMGeneric;
    case wvcdm::UNKNOWN_ERROR:
      return android::ERROR_DRM_UNKNOWN;
  }

  // Return here instead of as a default case so that the compiler will warn
  // us if we forget to include an enum member in the switch statement.
  return android::UNKNOWN_ERROR;
}

static inline bool isCdmResponseTypeSuccess(wvcdm::CdmResponseType res) {
  return mapCdmResponseType(res) == android::OK;
}

} // namespace wvdrm

#endif // WV_MAP_ERRORS_H_
