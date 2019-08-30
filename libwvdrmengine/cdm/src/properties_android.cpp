// Copyright 2013 Google Inc. All Rights Reserved.

#include "properties.h"

#include <sstream>
#include <string>
#include <unistd.h>

#include "cutils/properties.h"
#include "log.h"

namespace {

const char kBasePathPrefix[] = "/data/mediadrm/IDM";
const char kL1Dir[] = "/L1/";
const char kL2Dir[] = "/L2/";
const char kL3Dir[] = "/L3/";
const char kFactoryKeyboxPath[] = "/factory/wv.keys";

bool GetAndroidProperty(const char* key, std::string* value) {
  char val[PROPERTY_VALUE_MAX];
  if (!key) {
    LOGW("GetAndroidProperty: Invalid property key parameter");
    return false;
  }

  if (!value) {
    LOGW("GetAndroidProperty: Invalid property value parameter");
    return false;
  }

  if (property_get(key, val, "Unknown") <= 0) return false;

  *value = val;
  return true;
}

}  // namespace

namespace wvcdm {

bool Properties::GetCompanyName(std::string* company_name) {
  if (!company_name) {
    LOGW("Properties::GetCompanyName: Invalid parameter");
    return false;
  }
  return GetAndroidProperty("ro.product.manufacturer", company_name);
}

bool Properties::GetModelName(std::string* model_name) {
  if (!model_name) {
    LOGW("Properties::GetModelName: Invalid parameter");
    return false;
  }
  return GetAndroidProperty("ro.product.model", model_name);
}

bool Properties::GetArchitectureName(std::string* arch_name) {
  if (!arch_name) {
    LOGW("Properties::GetArchitectureName: Invalid parameter");
    return false;
  }
  return GetAndroidProperty("ro.product.cpu.abi", arch_name);
}

bool Properties::GetDeviceName(std::string* device_name) {
  if (!device_name) {
    LOGW("Properties::GetDeviceName: Invalid parameter");
    return false;
  }
  return GetAndroidProperty("ro.product.device", device_name);
}

bool Properties::GetProductName(std::string* product_name) {
  if (!product_name) {
    LOGW("Properties::GetProductName: Invalid parameter");
    return false;
  }
  return GetAndroidProperty("ro.product.name", product_name);
}

bool Properties::GetBuildInfo(std::string* build_info) {
  if (!build_info) {
    LOGW("Properties::GetBuildInfo: Invalid parameter");
    return false;
  }
  return GetAndroidProperty("ro.build.fingerprint", build_info);
}

bool Properties::GetDeviceFilesBasePath(CdmSecurityLevel security_level,
                                        std::string* base_path) {
  if (!base_path) {
    LOGW("Properties::GetDeviceFilesBasePath: Invalid parameter");
    return false;
  }
  std::stringstream ss;
  ss << kBasePathPrefix << getuid();
  switch (security_level) {
    case kSecurityLevelL1: ss << kL1Dir; break;
    case kSecurityLevelL2: ss << kL2Dir; break;
    case kSecurityLevelL3: ss << kL3Dir; break;
    default:
      LOGW("Properties::GetDeviceFilesBasePath: Unknown security level: %d",
           security_level);
      return false;
  }

  *base_path = ss.str();
  return true;
}

bool Properties::GetFactoryKeyboxPath(std::string* keybox) {
  if (!keybox) {
    LOGW("Properties::GetFactoryKeyboxPath: Invalid parameter");
    return false;
  }
  *keybox = kFactoryKeyboxPath;
  return true;
}

bool Properties::GetOEMCryptoPath(std::string* library_name) {
  if (!library_name) {
    LOGW("Properties::GetOEMCryptoPath: Invalid parameter");
    return false;
  }
  *library_name = "liboemcrypto.so";
  return true;
}

}  // namespace wvcdm
