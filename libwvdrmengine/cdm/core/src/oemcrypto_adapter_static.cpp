/*******************************************************************************
 *
 * Copyright 2013 Google Inc. All Rights Reserved.
 *
 * Wrapper of OEMCrypto APIs for platforms that support  Level 1 only.
 * This should be used when liboemcrypto.so is linked with the CDM code at
 * compile time.
 * An implementation should compile either oemcrypto_adapter_dynamic.cpp or
 * oemcrypto_adapter_static.cpp, but not both.
 *
 ******************************************************************************/

#include "OEMCryptoCENC.h"
#include "oemcrypto_adapter.h"

namespace wvcdm {

OEMCryptoResult OEMCrypto_OpenSession(OEMCrypto_SESSION* session,
                                      SecurityLevel level) {
  return ::OEMCrypto_OpenSession(session);
}

OEMCryptoResult OEMCrypto_IsKeyboxValid(SecurityLevel level) {
  return ::OEMCrypto_IsKeyboxValid();
}

OEMCryptoResult OEMCrypto_GetDeviceID(uint8_t* deviceID, size_t* idLength,
                                      SecurityLevel level) {
  return ::OEMCrypto_GetDeviceID(deviceID, idLength);
}

OEMCryptoResult OEMCrypto_GetKeyData(uint8_t* keyData, size_t* keyDataLength,
                                     SecurityLevel level) {
  return ::OEMCrypto_GetKeyData(keyData, keyDataLength);
}

OEMCryptoResult OEMCrypto_InstallKeybox(const uint8_t* keybox,
                                        size_t keyBoxLength,
                                        SecurityLevel level) {
  return ::OEMCrypto_InstallKeybox(keybox, keyBoxLength);
}

uint32_t OEMCrypto_APIVersion(SecurityLevel level) {
  return ::OEMCrypto_APIVersion();
}

const char* OEMCrypto_SecurityLevel(SecurityLevel level) {
  return ::OEMCrypto_SecurityLevel();
}

};  // namespace wvcdm
