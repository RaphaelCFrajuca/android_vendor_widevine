/*******************************************************************************
 *
 * Copyright 2013 Google Inc. All Rights Reserved.
 *
 * Wrapper of OEMCrypto APIs for platforms that support both Levels 1 and 3.
 * This should be used when liboemcrypto.so is dynamically loaded at run
 * time and not linked with the CDM code at compile time.
 * An implementation should compile either oemcrypto_adapter_dynamic.cpp or
 * oemcrypto_adapter_static.cpp, but not both.
 *
 ******************************************************************************/

#include "oemcrypto_adapter.h"

#include <dlfcn.h>
#include <stdio.h>
#include <iostream>
#include <cstring>
#include <string>
#include <map>

#include "level3.h"
#include "log.h"
#include "lock.h"
#include "file_store.h"
#include "properties.h"

using namespace wvoec3;

namespace wvcdm {

typedef OEMCryptoResult (*L1_Initialize_t)(void);
typedef OEMCryptoResult (*L1_Terminate_t)(void);
typedef OEMCryptoResult (*L1_OpenSession_t)(OEMCrypto_SESSION* session);
typedef OEMCryptoResult (*L1_CloseSession_t)(OEMCrypto_SESSION session);
typedef OEMCryptoResult (*L1_GenerateDerivedKeys_t)(
    OEMCrypto_SESSION session, const uint8_t* mac_key_context,
    uint32_t mac_key_context_length, const uint8_t* enc_key_context,
    uint32_t enc_key_context_length);
typedef OEMCryptoResult (*L1_GenerateNonce_t)(OEMCrypto_SESSION session,
                                              uint32_t* nonce);
typedef OEMCryptoResult (*L1_GenerateSignature_t)(OEMCrypto_SESSION session,
                                                  const uint8_t* message,
                                                  size_t message_length,
                                                  uint8_t* signature,
                                                  size_t* signature_length);
typedef OEMCryptoResult (*L1_LoadKeys_t)(
    OEMCrypto_SESSION session, const uint8_t* message, size_t message_length,
    const uint8_t* signature, size_t signature_length,
    const uint8_t* enc_mac_key_iv, const uint8_t* enc_mac_key, size_t num_keys,
    const OEMCrypto_KeyObject* key_array);
typedef OEMCryptoResult (*L1_RefreshKeys_t)(
    OEMCrypto_SESSION session, const uint8_t* message, size_t message_length,
    const uint8_t* signature, size_t signature_length, size_t num_keys,
    const OEMCrypto_KeyRefreshObject* key_array);
typedef OEMCryptoResult (*L1_SelectKey_t)(const OEMCrypto_SESSION session,
                                          const uint8_t* key_id,
                                          size_t key_id_length);
typedef OEMCryptoResult (*L1_DecryptCTR_t)(
    OEMCrypto_SESSION session, const uint8_t* data_addr, size_t data_length,
    bool is_encrypted, const uint8_t* iv, size_t offset,
    const OEMCrypto_DestBufferDesc* out_buffer, uint8_t subsample_flags);
typedef OEMCryptoResult (*L1_InstallKeybox_t)(const uint8_t* keybox,
                                              size_t keyBoxLength);
typedef OEMCryptoResult (*L1_IsKeyboxValid_t)(void);
typedef OEMCryptoResult (*L1_GetDeviceID_t)(uint8_t* deviceID,
                                            size_t* idLength);
typedef OEMCryptoResult (*L1_GetKeyData_t)(uint8_t* keyData,
                                           size_t* keyDataLength);
typedef OEMCryptoResult (*L1_GetRandom_t)(uint8_t* randomData,
                                          size_t dataLength);
typedef OEMCryptoResult (*L1_WrapKeybox_t)(const uint8_t* keybox,
                                           size_t keyBoxLength,
                                           uint8_t* wrappedKeybox,
                                           size_t* wrappedKeyBoxLength,
                                           const uint8_t* transportKey,
                                           size_t transportKeyLength);
typedef OEMCryptoResult (*L1_RewrapDeviceRSAKey_t)(
    OEMCrypto_SESSION session, const uint8_t* message, size_t message_length,
    const uint8_t* signature, size_t signature_length, const uint32_t* nonce,
    const uint8_t* enc_rsa_key, size_t enc_rsa_key_length,
    const uint8_t* enc_rsa_key_iv, uint8_t* wrapped_rsa_key,
    size_t* wrapped_rsa_key_length);
typedef OEMCryptoResult (*L1_LoadDeviceRSAKey_t)(OEMCrypto_SESSION session,
                                                 const uint8_t* wrapped_rsa_key,
                                                 size_t wrapped_rsa_key_length);
typedef OEMCryptoResult (*L1_GenerateRSASignature_t)(OEMCrypto_SESSION session,
                                                     const uint8_t* message,
                                                     size_t message_length,
                                                     uint8_t* signature,
                                                     size_t* signature_length);
typedef OEMCryptoResult (*L1_DeriveKeysFromSessionKey_t)(
    OEMCrypto_SESSION session, const uint8_t* enc_session_key,
    size_t enc_session_key_length, const uint8_t* mac_key_context,
    size_t mac_key_context_length, const uint8_t* enc_key_context,
    size_t enc_key_context_length);
typedef OEMCryptoResult (*L1_Generic_Encrypt_t)(
    OEMCrypto_SESSION session, const uint8_t* in_buffer, size_t buffer_length,
    const uint8_t* iv, OEMCrypto_Algorithm algorithm, uint8_t* out_buffer);
typedef OEMCryptoResult (*L1_Generic_Decrypt_t)(
    OEMCrypto_SESSION session, const uint8_t* in_buffer, size_t buffer_length,
    const uint8_t* iv, OEMCrypto_Algorithm algorithm, uint8_t* out_buffer);

typedef OEMCryptoResult (*L1_Generic_Sign_t)(OEMCrypto_SESSION session,
                                             const uint8_t* in_buffer,
                                             size_t buffer_length,
                                             OEMCrypto_Algorithm algorithm,
                                             uint8_t* signature,
                                             size_t* signature_length);

typedef OEMCryptoResult (*L1_Generic_Verify_t)(OEMCrypto_SESSION session,
                                               const uint8_t* in_buffer,
                                               size_t buffer_length,
                                               OEMCrypto_Algorithm algorithm,
                                               const uint8_t* signature,
                                               size_t signature_length);
typedef uint32_t (*L1_APIVersion_t)();
typedef const char* (*L1_SecurityLevel_t)();

struct FunctionPointers {
  L1_Initialize_t Initialize;
  L1_Terminate_t Terminate;
  L1_OpenSession_t OpenSession;
  L1_CloseSession_t CloseSession;
  L1_GenerateDerivedKeys_t GenerateDerivedKeys;
  L1_GenerateNonce_t GenerateNonce;
  L1_GenerateSignature_t GenerateSignature;
  L1_LoadKeys_t LoadKeys;
  L1_RefreshKeys_t RefreshKeys;
  L1_SelectKey_t SelectKey;
  L1_DecryptCTR_t DecryptCTR;
  L1_InstallKeybox_t InstallKeybox;
  L1_IsKeyboxValid_t IsKeyboxValid;
  L1_GetDeviceID_t GetDeviceID;
  L1_GetKeyData_t GetKeyData;
  L1_GetRandom_t GetRandom;
  L1_WrapKeybox_t WrapKeybox;
  L1_RewrapDeviceRSAKey_t RewrapDeviceRSAKey;
  L1_LoadDeviceRSAKey_t LoadDeviceRSAKey;
  L1_GenerateRSASignature_t GenerateRSASignature;
  L1_DeriveKeysFromSessionKey_t DeriveKeysFromSessionKey;
  L1_APIVersion_t APIVersion;
  L1_SecurityLevel_t SecurityLevel;
  L1_Generic_Encrypt_t Generic_Encrypt;
  L1_Generic_Decrypt_t Generic_Decrypt;
  L1_Generic_Sign_t Generic_Sign;
  L1_Generic_Verify_t Generic_Verify;
};

struct LevelSession {
  FunctionPointers* fcn;
  OEMCrypto_SESSION session;
  LevelSession() : fcn(0), session(0) {};
};

#define QUOTE_DEFINE(A) #A
#define QUOTE(A) QUOTE_DEFINE(A)
#define LOOKUP(Name, Function)                                        \
  level1_.Name =                                                      \
      (L1_##Name##_t)dlsym(level1_library_, QUOTE(Function)); \
  if (!level1_.Name) {                                                \
    LOGW("Could not load L1 %s. Falling Back to L3.",                 \
         QUOTE(OEMCrypto_##Name));                                    \
    return false;                                                     \
  }

class Adapter {
 public:
  typedef std::map<OEMCrypto_SESSION, LevelSession>::iterator map_iterator;

  Adapter() : level1_valid_(false), level1_library_(NULL) {}

  ~Adapter() {
    for (map_iterator i = session_map_.begin(); i != session_map_.end(); i++) {
      if (i->second.fcn) i->second.fcn->CloseSession(i->second.session);
    }
    session_map_.clear();
  }

  OEMCryptoResult Initialize() {
    LoadLevel3();
    OEMCryptoResult result = Level3_Initialize();
    std::string library_name;
    if (!wvcdm::Properties::GetOEMCryptoPath(&library_name)) {
      LOGW("L1 library not specified. Falling Back to L3");
      return result;
    }
    level1_library_ = dlopen(library_name.c_str(), RTLD_NOW);
    if (level1_library_ == NULL) {
      LOGW("Could not load %s. Falling Back to L3.  %s", library_name.c_str(),
           dlerror());
      return result;
    }
    if (LoadLevel1()) {
      LOGD("OEMCrypto_Initialize Level 1 success. I will use level 1.");
    } else {
      dlclose(level1_library_);
      level1_library_ = NULL;
      level1_valid_ = false;
    }
    return result;
  }

  bool LoadLevel1() {
    level1_valid_ = true;
    LOOKUP(Initialize,               OEMCrypto_Initialize);
    LOOKUP(Terminate,                OEMCrypto_Terminate);
    LOOKUP(OpenSession,              OEMCrypto_OpenSession);
    LOOKUP(CloseSession,             OEMCrypto_CloseSession);
    LOOKUP(GenerateDerivedKeys,      OEMCrypto_GenerateDerivedKeys);
    LOOKUP(GenerateNonce,            OEMCrypto_GenerateNonce);
    LOOKUP(GenerateSignature,        OEMCrypto_GenerateSignature);
    LOOKUP(LoadKeys,                 OEMCrypto_LoadKeys);
    LOOKUP(RefreshKeys,              OEMCrypto_RefreshKeys);
    LOOKUP(SelectKey,                OEMCrypto_SelectKey);
    LOOKUP(DecryptCTR,               OEMCrypto_DecryptCTR);
    LOOKUP(InstallKeybox,            OEMCrypto_InstallKeybox);
    LOOKUP(IsKeyboxValid,            OEMCrypto_IsKeyboxValid);
    LOOKUP(GetDeviceID,              OEMCrypto_GetDeviceID);
    LOOKUP(GetKeyData,               OEMCrypto_GetKeyData);
    LOOKUP(GetRandom,                OEMCrypto_GetRandom);
    LOOKUP(WrapKeybox,               OEMCrypto_WrapKeybox);
    LOOKUP(RewrapDeviceRSAKey,       OEMCrypto_RewrapDeviceRSAKey);
    LOOKUP(LoadDeviceRSAKey,         OEMCrypto_LoadDeviceRSAKey);
    LOOKUP(GenerateRSASignature,     OEMCrypto_GenerateRSASignature);
    LOOKUP(DeriveKeysFromSessionKey, OEMCrypto_DeriveKeysFromSessionKey);
    LOOKUP(APIVersion,               OEMCrypto_APIVersion);
    LOOKUP(SecurityLevel,            OEMCrypto_SecurityLevel);
    LOOKUP(Generic_Decrypt,          OEMCrypto_Generic_Decrypt);
    LOOKUP(Generic_Encrypt,          OEMCrypto_Generic_Encrypt);
    LOOKUP(Generic_Sign,             OEMCrypto_Generic_Sign);
    LOOKUP(Generic_Verify,           OEMCrypto_Generic_Verify);
    if (!level1_valid_) {
      return false;
    }
    OEMCryptoResult st = level1_.Initialize();
    if (st != OEMCrypto_SUCCESS) {
      LOGW("Could not initialize L1. Falling Back to L3.");
      return false;
    }
    uint32_t level1_version = level1_.APIVersion();
    if (level1_version != oec_latest_version) {
      LOGW("liboemcrypto.so is version %d, not %d. Falling Back to L3.",
           level1_version, oec_latest_version);
      return false;
    }
    if (OEMCrypto_SUCCESS == level1_.IsKeyboxValid()) {
      return true;
    }
    wvcdm::File file;
    std::string filename;
    if (!wvcdm::Properties::GetFactoryKeyboxPath(&filename)) {
      LOGW("Bad Level 1 Keybox. Falling Back to L3.");
      return false;
    }
    ssize_t size = file.FileSize(filename);
    if (size <= 0 || !file.Open(filename, file.kBinary | file.kReadOnly)) {
      LOGW("Could not open %s. Falling Back to L3.", filename.c_str());
      return false;
    }
    uint8_t keybox[size];
    ssize_t size_read = file.Read(reinterpret_cast<char*>(keybox), size);
    if (level1_.InstallKeybox(keybox, size) != OEMCrypto_SUCCESS) {
      LOGE("Could NOT install keybox from %s. Falling Back to L3.",
           filename.c_str());
      false;
    }
    LOGI("Installed keybox from %s", filename.c_str());
    return true;
  }

  void LoadLevel3() {
    level3_.Initialize = Level3_Initialize;
    level3_.Terminate = Level3_Terminate;
    level3_.OpenSession = Level3_OpenSession;
    level3_.CloseSession = Level3_CloseSession;
    level3_.GenerateDerivedKeys = Level3_GenerateDerivedKeys;
    level3_.GenerateNonce = Level3_GenerateNonce;
    level3_.GenerateSignature = Level3_GenerateSignature;
    level3_.LoadKeys = Level3_LoadKeys;
    level3_.RefreshKeys = Level3_RefreshKeys;
    level3_.SelectKey = Level3_SelectKey;
    level3_.DecryptCTR = Level3_DecryptCTR;
    level3_.InstallKeybox = Level3_InstallKeybox;
    level3_.IsKeyboxValid = Level3_IsKeyboxValid;
    level3_.GetDeviceID = Level3_GetDeviceID;
    level3_.GetKeyData = Level3_GetKeyData;
    level3_.GetRandom = Level3_GetRandom;
    level3_.WrapKeybox = Level3_WrapKeybox;
    level3_.RewrapDeviceRSAKey = Level3_RewrapDeviceRSAKey;
    level3_.LoadDeviceRSAKey = Level3_LoadDeviceRSAKey;
    level3_.GenerateRSASignature = Level3_GenerateRSASignature;
    level3_.DeriveKeysFromSessionKey = Level3_DeriveKeysFromSessionKey;
    level3_.APIVersion = Level3_APIVersion;
    level3_.SecurityLevel = Level3_SecurityLevel;
    level3_.Generic_Decrypt = Level3_Generic_Decrypt;
    level3_.Generic_Encrypt = Level3_Generic_Encrypt;
    level3_.Generic_Sign = Level3_Generic_Sign;
    level3_.Generic_Verify = Level3_Generic_Verify;
  }

  OEMCryptoResult Terminate() {
    OEMCryptoResult result = Level3_Terminate();
    if (level1_valid_) {
      result = level1_.Terminate();
      dlclose(level1_library_);
      level1_library_ = NULL;
    }
    return result;
  }

  const FunctionPointers* get(SecurityLevel level) {
    if (level1_valid_ && level == kLevelDefault) return &level1_;
    return &level3_;
  }

  LevelSession get(OEMCrypto_SESSION session) {
    AutoLock auto_lock(lookup_lock_);
    map_iterator pair = session_map_.find(session);
    if (pair == session_map_.end()) {
      return LevelSession();
    }
    return pair->second;
  }

  OEMCryptoResult OpenSession(OEMCrypto_SESSION* session, SecurityLevel level) {
    AutoLock auto_lock(lookup_lock_);
    LevelSession new_session;
    OEMCryptoResult result;
    if (level == kLevelDefault && level1_valid_) {
      new_session.fcn = &level1_;
      result = level1_.OpenSession(&new_session.session);
      *session = new_session.session;
    } else {
      new_session.fcn = &level3_;
      result = level3_.OpenSession(&new_session.session);
      *session = new_session.session + kLevel3Offset;
    }
    if (result == OEMCrypto_SUCCESS) {
      // Make sure session is not already in my list of sessions.
      while (session_map_.find(*session) != session_map_.end()) {
        (*session)++;
      }
      session_map_[*session] = new_session;
    }
    return result;
  }

  OEMCryptoResult CloseSession(OEMCrypto_SESSION session) {
    AutoLock auto_lock(lookup_lock_);
    map_iterator pair = session_map_.find(session);
    if (pair == session_map_.end()) {
      return OEMCrypto_ERROR_INVALID_SESSION;
    }
    OEMCryptoResult result =
        pair->second.fcn->CloseSession(pair->second.session);
    session_map_.erase(pair);
    return result;
  }

 private:
  bool level1_valid_;
  void* level1_library_;
  struct FunctionPointers level1_;
  struct FunctionPointers level3_;
  std::map<OEMCrypto_SESSION, LevelSession> session_map_;
  Lock lookup_lock_;
  // This is just for debugging the map between session ids.
  // If we add this to the level 3 session id, then the external session
  // id will match the internal session id in the last two digits.
  static const OEMCrypto_SESSION kLevel3Offset = 25600;
};
static Adapter* kAdapter = 0;

extern "C" OEMCryptoResult OEMCrypto_Initialize(void) {
  if (kAdapter) {
    delete kAdapter;
  }
  kAdapter = new Adapter();
  return kAdapter->Initialize();
}

extern "C" OEMCryptoResult OEMCrypto_Terminate(void) {
  OEMCryptoResult result = OEMCrypto_SUCCESS;
  if (kAdapter) {
    result = kAdapter->Terminate();
    delete kAdapter;
  }
  kAdapter = NULL;
  return result;
}

extern "C" OEMCryptoResult OEMCrypto_OpenSession(OEMCrypto_SESSION* session) {
  return OEMCrypto_OpenSession(session, kLevelDefault);
}

OEMCryptoResult OEMCrypto_OpenSession(OEMCrypto_SESSION* session,
                                      SecurityLevel level) {
  if (!kAdapter) return OEMCrypto_ERROR_OPEN_SESSION_FAILED;
  return kAdapter->OpenSession(session, level);
}

extern "C" OEMCryptoResult OEMCrypto_CloseSession(OEMCrypto_SESSION session) {
  if (!kAdapter) return OEMCrypto_ERROR_CLOSE_SESSION_FAILED;
  return kAdapter->CloseSession(session);
}

extern "C" OEMCryptoResult OEMCrypto_GenerateNonce(OEMCrypto_SESSION session,
                                                   uint32_t* nonce) {
  if (!kAdapter) return OEMCrypto_ERROR_UNKNOWN_FAILURE;
  LevelSession pair = kAdapter->get(session);
  if (!pair.fcn) return OEMCrypto_ERROR_INVALID_SESSION;
  return pair.fcn->GenerateNonce(pair.session, nonce);
}

extern "C" OEMCryptoResult OEMCrypto_GenerateDerivedKeys(
    OEMCrypto_SESSION session, const uint8_t* mac_key_context,
    uint32_t mac_key_context_length, const uint8_t* enc_key_context,
    uint32_t enc_key_context_length) {
  if (!kAdapter) return OEMCrypto_ERROR_UNKNOWN_FAILURE;
  LevelSession pair = kAdapter->get(session);
  if (!pair.fcn) return OEMCrypto_ERROR_INVALID_SESSION;
  return pair.fcn->GenerateDerivedKeys(pair.session, mac_key_context,
                                       mac_key_context_length, enc_key_context,
                                       enc_key_context_length);
}

extern "C" OEMCryptoResult OEMCrypto_GenerateSignature(
    OEMCrypto_SESSION session, const uint8_t* message, size_t message_length,
    uint8_t* signature, size_t* signature_length) {
  if (!kAdapter) return OEMCrypto_ERROR_UNKNOWN_FAILURE;
  LevelSession pair = kAdapter->get(session);
  if (!pair.fcn) return OEMCrypto_ERROR_INVALID_SESSION;
  return pair.fcn->GenerateSignature(pair.session, message, message_length,
                                     signature, signature_length);
}

extern "C" OEMCryptoResult OEMCrypto_LoadKeys(
    OEMCrypto_SESSION session, const uint8_t* message, size_t message_length,
    const uint8_t* signature, size_t signature_length,
    const uint8_t* enc_mac_key_iv, const uint8_t* enc_mac_key, size_t num_keys,
    const OEMCrypto_KeyObject* key_array) {
  if (!kAdapter) return OEMCrypto_ERROR_UNKNOWN_FAILURE;
  LevelSession pair = kAdapter->get(session);
  if (!pair.fcn) return OEMCrypto_ERROR_INVALID_SESSION;
  return pair.fcn->LoadKeys(pair.session, message, message_length, signature,
                            signature_length, enc_mac_key_iv, enc_mac_key,
                            num_keys, key_array);
}

extern "C" OEMCryptoResult OEMCrypto_RefreshKeys(
    OEMCrypto_SESSION session, const uint8_t* message, size_t message_length,
    const uint8_t* signature, size_t signature_length, size_t num_keys,
    const OEMCrypto_KeyRefreshObject* key_array) {
  if (!kAdapter) return OEMCrypto_ERROR_UNKNOWN_FAILURE;
  LevelSession pair = kAdapter->get(session);
  if (!pair.fcn) return OEMCrypto_ERROR_INVALID_SESSION;
  return pair.fcn->RefreshKeys(pair.session, message, message_length, signature,
                               signature_length, num_keys, key_array);
}

extern "C" OEMCryptoResult OEMCrypto_SelectKey(const OEMCrypto_SESSION session,
                                               const uint8_t* key_id,
                                               size_t key_id_length) {
  if (!kAdapter) return OEMCrypto_ERROR_UNKNOWN_FAILURE;
  LevelSession pair = kAdapter->get(session);
  if (!pair.fcn) return OEMCrypto_ERROR_INVALID_SESSION;
  return pair.fcn->SelectKey(pair.session, key_id, key_id_length);
}

extern "C" OEMCryptoResult OEMCrypto_DecryptCTR(
    OEMCrypto_SESSION session, const uint8_t* data_addr, size_t data_length,
    bool is_encrypted, const uint8_t* iv, size_t offset,
    const OEMCrypto_DestBufferDesc* out_buffer, uint8_t subsample_flags) {
  if (!kAdapter) return OEMCrypto_ERROR_UNKNOWN_FAILURE;
  LevelSession pair = kAdapter->get(session);
  if (!pair.fcn) return OEMCrypto_ERROR_INVALID_SESSION;
  return pair.fcn->DecryptCTR(pair.session, data_addr, data_length,
                              is_encrypted, iv, offset, out_buffer,
                              subsample_flags);
}

extern "C" OEMCryptoResult OEMCrypto_InstallKeybox(const uint8_t* keybox,
                                                   size_t keyBoxLength) {
  return OEMCrypto_InstallKeybox(keybox, keyBoxLength, kLevelDefault);
}

OEMCryptoResult OEMCrypto_InstallKeybox(const uint8_t* keybox,
                                        size_t keyBoxLength,
                                        SecurityLevel level) {
  if (!kAdapter) return OEMCrypto_ERROR_UNKNOWN_FAILURE;
  const FunctionPointers* fcn = kAdapter->get(level);
  if (!fcn) return OEMCrypto_ERROR_INVALID_SESSION;
  return fcn->InstallKeybox(keybox, keyBoxLength);
}

extern "C" OEMCryptoResult OEMCrypto_IsKeyboxValid() {
  return OEMCrypto_IsKeyboxValid(kLevelDefault);
}

OEMCryptoResult OEMCrypto_IsKeyboxValid(SecurityLevel level) {
  if (!kAdapter) return OEMCrypto_ERROR_UNKNOWN_FAILURE;
  const FunctionPointers* fcn = kAdapter->get(level);
  if (!fcn) return OEMCrypto_ERROR_INVALID_SESSION;
  return fcn->IsKeyboxValid();
}

extern "C" OEMCryptoResult OEMCrypto_GetDeviceID(uint8_t* deviceID,
                                                 size_t* idLength) {
  return OEMCrypto_GetDeviceID(deviceID, idLength, kLevelDefault);
}

OEMCryptoResult OEMCrypto_GetDeviceID(uint8_t* deviceID, size_t* idLength,
                                      SecurityLevel level) {
  if (!kAdapter) return OEMCrypto_ERROR_UNKNOWN_FAILURE;
  const FunctionPointers* fcn = kAdapter->get(level);
  if (!fcn) return OEMCrypto_ERROR_INVALID_SESSION;
  return fcn->GetDeviceID(deviceID, idLength);
}

extern "C" OEMCryptoResult OEMCrypto_GetKeyData(uint8_t* keyData,
                                                size_t* keyDataLength) {
  return OEMCrypto_GetKeyData(keyData, keyDataLength, kLevelDefault);
}

OEMCryptoResult OEMCrypto_GetKeyData(uint8_t* keyData, size_t* keyDataLength,
                                     SecurityLevel level) {
  if (!kAdapter) return OEMCrypto_ERROR_UNKNOWN_FAILURE;
  const FunctionPointers* fcn = kAdapter->get(level);
  if (!fcn) return OEMCrypto_ERROR_INVALID_SESSION;
  return fcn->GetKeyData(keyData, keyDataLength);
}

extern "C" OEMCryptoResult OEMCrypto_GetRandom(uint8_t* randomData,
                                               size_t dataLength) {
  if (!kAdapter) return OEMCrypto_ERROR_UNKNOWN_FAILURE;
  const FunctionPointers* fcn = kAdapter->get(kLevelDefault);
  if (!fcn) return OEMCrypto_ERROR_INVALID_SESSION;
  return fcn->GetRandom(randomData, dataLength);
}

extern "C" OEMCryptoResult OEMCrypto_WrapKeybox(const uint8_t* keybox,
                                                size_t keyBoxLength,
                                                uint8_t* wrappedKeybox,
                                                size_t* wrappedKeyBoxLength,
                                                const uint8_t* transportKey,
                                                size_t transportKeyLength) {
  if (!kAdapter) return OEMCrypto_ERROR_UNKNOWN_FAILURE;
  const FunctionPointers* fcn = kAdapter->get(kLevelDefault);
  if (!fcn) return OEMCrypto_ERROR_INVALID_SESSION;
  return fcn->WrapKeybox(keybox, keyBoxLength, wrappedKeybox,
                         wrappedKeyBoxLength, transportKey, transportKeyLength);
}

extern "C" OEMCryptoResult OEMCrypto_RewrapDeviceRSAKey(
    OEMCrypto_SESSION session, const uint8_t* message, size_t message_length,
    const uint8_t* signature, size_t signature_length, const uint32_t* nonce,
    const uint8_t* enc_rsa_key, size_t enc_rsa_key_length,
    const uint8_t* enc_rsa_key_iv, uint8_t* wrapped_rsa_key,
    size_t* wrapped_rsa_key_length) {
  if (!kAdapter) return OEMCrypto_ERROR_UNKNOWN_FAILURE;
  LevelSession pair = kAdapter->get(session);
  if (!pair.fcn) return OEMCrypto_ERROR_INVALID_SESSION;
  return pair.fcn->RewrapDeviceRSAKey(
      pair.session, message, message_length, signature, signature_length, nonce,
      enc_rsa_key, enc_rsa_key_length, enc_rsa_key_iv, wrapped_rsa_key,
      wrapped_rsa_key_length);
}

extern "C" OEMCryptoResult OEMCrypto_LoadDeviceRSAKey(
    OEMCrypto_SESSION session, const uint8_t* wrapped_rsa_key,
    size_t wrapped_rsa_key_length) {
  if (!kAdapter) return OEMCrypto_ERROR_UNKNOWN_FAILURE;
  LevelSession pair = kAdapter->get(session);
  if (!pair.fcn) return OEMCrypto_ERROR_INVALID_SESSION;
  return pair.fcn
      ->LoadDeviceRSAKey(pair.session, wrapped_rsa_key, wrapped_rsa_key_length);
}

extern "C" OEMCryptoResult OEMCrypto_GenerateRSASignature(
    OEMCrypto_SESSION session, const uint8_t* message, size_t message_length,
    uint8_t* signature, size_t* signature_length) {
  if (!kAdapter) return OEMCrypto_ERROR_UNKNOWN_FAILURE;
  LevelSession pair = kAdapter->get(session);
  if (!pair.fcn) return OEMCrypto_ERROR_INVALID_SESSION;
  return pair.fcn->GenerateRSASignature(pair.session, message, message_length,
                                        signature, signature_length);
}

extern "C" OEMCryptoResult OEMCrypto_DeriveKeysFromSessionKey(
    OEMCrypto_SESSION session, const uint8_t* enc_session_key,
    size_t enc_session_key_length, const uint8_t* mac_key_context,
    size_t mac_key_context_length, const uint8_t* enc_key_context,
    size_t enc_key_context_length) {
  if (!kAdapter) return OEMCrypto_ERROR_UNKNOWN_FAILURE;
  LevelSession pair = kAdapter->get(session);
  if (!pair.fcn) return OEMCrypto_ERROR_INVALID_SESSION;
  return pair.fcn->DeriveKeysFromSessionKey(
      pair.session, enc_session_key, enc_session_key_length, mac_key_context,
      mac_key_context_length, enc_key_context, enc_key_context_length);
}

extern "C" uint32_t OEMCrypto_APIVersion() {
  return OEMCrypto_APIVersion(kLevelDefault);
}

uint32_t OEMCrypto_APIVersion(SecurityLevel level) {
  if (!kAdapter) return 0;
  const FunctionPointers* fcn = kAdapter->get(level);
  if (!fcn) return 0;
  return fcn->APIVersion();
}

extern "C" const char* OEMCrypto_SecurityLevel() {
  return OEMCrypto_SecurityLevel(kLevelDefault);
}

const char* OEMCrypto_SecurityLevel(SecurityLevel level) {
  if (!kAdapter) return "";
  const FunctionPointers* fcn = kAdapter->get(level);
  if (!fcn) return "";
  return fcn->SecurityLevel();
}

extern "C" OEMCryptoResult OEMCrypto_Generic_Encrypt(
    OEMCrypto_SESSION session, const uint8_t* in_buffer, size_t buffer_length,
    const uint8_t* iv, OEMCrypto_Algorithm algorithm, uint8_t* out_buffer) {

  if (!kAdapter) return OEMCrypto_ERROR_UNKNOWN_FAILURE;
  LevelSession pair = kAdapter->get(session);
  if (!pair.fcn) return OEMCrypto_ERROR_INVALID_SESSION;
  return pair.fcn->Generic_Encrypt(pair.session, in_buffer, buffer_length, iv,
                                   algorithm, out_buffer);
}

extern "C" OEMCryptoResult OEMCrypto_Generic_Decrypt(
    OEMCrypto_SESSION session, const uint8_t* in_buffer, size_t buffer_length,
    const uint8_t* iv, OEMCrypto_Algorithm algorithm, uint8_t* out_buffer) {
  if (!kAdapter) return OEMCrypto_ERROR_UNKNOWN_FAILURE;
  LevelSession pair = kAdapter->get(session);
  if (!pair.fcn) return OEMCrypto_ERROR_INVALID_SESSION;
  return pair.fcn->Generic_Decrypt(pair.session, in_buffer, buffer_length, iv,
                                   algorithm, out_buffer);
}

extern "C" OEMCryptoResult OEMCrypto_Generic_Sign(OEMCrypto_SESSION session,
                                                  const uint8_t* in_buffer,
                                                  size_t buffer_length,
                                                  OEMCrypto_Algorithm algorithm,
                                                  uint8_t* signature,
                                                  size_t* signature_length) {
  if (!kAdapter) return OEMCrypto_ERROR_UNKNOWN_FAILURE;
  LevelSession pair = kAdapter->get(session);
  if (!pair.fcn) return OEMCrypto_ERROR_INVALID_SESSION;
  return pair.fcn->Generic_Sign(pair.session, in_buffer, buffer_length,
                                algorithm, signature, signature_length);
}

extern "C" OEMCryptoResult OEMCrypto_Generic_Verify(
    OEMCrypto_SESSION session, const uint8_t* in_buffer, size_t buffer_length,
    OEMCrypto_Algorithm algorithm, const uint8_t* signature,
    size_t signature_length) {
  if (!kAdapter) return OEMCrypto_ERROR_UNKNOWN_FAILURE;
  LevelSession pair = kAdapter->get(session);
  if (!pair.fcn) return OEMCrypto_ERROR_INVALID_SESSION;
  return pair.fcn->Generic_Verify(pair.session, in_buffer, buffer_length,
                                  algorithm, signature, signature_length);
}

};  // namespace wvcdm
