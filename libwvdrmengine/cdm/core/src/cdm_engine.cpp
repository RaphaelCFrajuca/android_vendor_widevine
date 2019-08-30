// Copyright 2013 Google Inc. All Rights Reserved.

#include "cdm_engine.h"

#include <iostream>
#include <sstream>

#include "buffer_reader.h"
#include "cdm_session.h"
#include "license_protocol.pb.h"
#include "log.h"
#include "properties.h"
#include "scoped_ptr.h"
#include "string_conversions.h"
#include "wv_cdm_constants.h"
#include "wv_cdm_event_listener.h"

namespace {
const int kCdmPolicyTimerDurationSeconds = 1;
}

namespace wvcdm {

CdmEngine::CdmEngine()
    : cert_provisioning_requested_security_level_(kLevelDefault) {
  Properties::Init();
}

CdmEngine::~CdmEngine() {
  CancelSessions();

  DisablePolicyTimer(true);
  CdmSessionMap::iterator i(sessions_.begin());
  for (; i != sessions_.end(); ++i)
    delete i->second;
  sessions_.clear();
}

CdmResponseType CdmEngine::OpenSession(
    const CdmKeySystem& key_system,
    const CdmClientPropertySet* property_set,
    CdmSessionId* session_id) {
  LOGI("CdmEngine::OpenSession");

  if (!ValidateKeySystem(key_system)) {
    LOGI("CdmEngine::OpenSession: invalid key_system = %s", key_system.c_str());
    return KEY_ERROR;
  }

  if (!session_id) {
    LOGE("CdmEngine::OpenSession: no session ID destination provided");
    return KEY_ERROR;
  }

  scoped_ptr<CdmSession> new_session(new CdmSession(property_set));
  if (new_session->session_id().empty()) {
    LOGE("CdmEngine::OpenSession: failure to generate session ID");
    return UNKNOWN_ERROR;
  }

  CdmResponseType sts = new_session->Init();
  if (sts != NO_ERROR) {
    if (sts == NEED_PROVISIONING) {
      cert_provisioning_requested_security_level_ =
          new_session->GetRequestedSecurityLevel();
    }
    LOGE("CdmEngine::OpenSession: bad session init: %u", sts);
    return sts;
  }
  *session_id = new_session->session_id();
  sessions_[*session_id] = new_session.release();
  return NO_ERROR;
}

CdmResponseType CdmEngine::OpenKeySetSession(const CdmKeySetId& key_set_id) {
  LOGI("CdmEngine::OpenKeySetSession");

  if (key_set_id.empty()) {
    LOGE("CdmEngine::OpenKeySetSession: invalid key set id");
    return KEY_ERROR;
  }

  CdmSessionId session_id;
  CdmResponseType sts = OpenSession(KEY_SYSTEM, NULL, &session_id);

  if (sts != NO_ERROR)
    return sts;

  release_key_sets_[key_set_id] = session_id;
  return NO_ERROR;
}

CdmResponseType CdmEngine::CloseSession(const CdmSessionId& session_id) {
  LOGI("CdmEngine::CloseSession");

  CdmSessionMap::iterator iter = sessions_.find(session_id);
  if (iter == sessions_.end()) {
    LOGE("CdmEngine::CloseSession: session not found = %s", session_id.c_str());
    return KEY_ERROR;
  }

  CdmSession* session = iter->second;
  sessions_.erase(session_id);
  DisablePolicyTimer(false);
  delete session;
  return NO_ERROR;
}

CdmResponseType CdmEngine::CloseKeySetSession(const CdmKeySetId& key_set_id) {
  LOGI("CdmEngine::CloseKeySetSession");

  CdmReleaseKeySetMap::iterator iter = release_key_sets_.find(key_set_id);
  if (iter == release_key_sets_.end()) {
    LOGE("CdmEngine::CloseKeySetSession: key set id not found = %s",
        key_set_id.c_str());
    return KEY_ERROR;
  }

  CdmResponseType sts = CloseSession(iter->second);
  release_key_sets_.erase(iter);
  return sts;
}

CdmResponseType CdmEngine::GenerateKeyRequest(
    const CdmSessionId& session_id,
    const CdmKeySetId& key_set_id,
    const CdmInitData& init_data,
    const CdmLicenseType license_type,
    CdmAppParameterMap& app_parameters,
    CdmKeyMessage* key_request,
    std::string* server_url) {
  LOGI("CdmEngine::GenerateKeyRequest");

  CdmSessionId id = session_id;
  CdmResponseType sts;

  if (license_type == kLicenseTypeRelease) {
    if (key_set_id.empty()) {
      LOGE("CdmEngine::GenerateKeyRequest: invalid key set ID");
      return UNKNOWN_ERROR;
    }

    if (!session_id.empty()) {
      LOGE("CdmEngine::GenerateKeyRequest: invalid session ID = %s",
          session_id.c_str());
      return UNKNOWN_ERROR;
    }

    CdmReleaseKeySetMap::iterator iter = release_key_sets_.find(key_set_id);
    if (iter == release_key_sets_.end()) {
      LOGE("CdmEngine::GenerateKeyRequest: key set ID not found = %s",
          key_set_id.c_str());
      return UNKNOWN_ERROR;
    }

    id = iter->second;
  }

  CdmSessionMap::iterator iter = sessions_.find(id);
  if (iter == sessions_.end()) {
    LOGE("CdmEngine::GenerateKeyRequest: session_id not found = %s",
        id.c_str());
    return KEY_ERROR;
  }

  if (!key_request) {
    LOGE("CdmEngine::GenerateKeyRequest: no key request destination provided");
    return KEY_ERROR;
  }

  key_request->clear();

  if (license_type == kLicenseTypeRelease) {
    sts = iter->second->RestoreOfflineSession(key_set_id, kLicenseTypeRelease);
    if (sts != KEY_ADDED) {
      LOGE("CdmEngine::GenerateKeyRequest: key release restoration failed,"
          "sts = %d", (int)sts);
      return sts;
    }
  }

  sts = iter->second->GenerateKeyRequest(init_data, license_type,
                                         app_parameters, key_request,
                                         server_url);

  if (KEY_MESSAGE != sts) {
    if (sts == NEED_PROVISIONING) {
      cert_provisioning_requested_security_level_ =
          iter->second->GetRequestedSecurityLevel();
    }
    LOGE("CdmEngine::GenerateKeyRequest: key request generation failed, "
        "sts = %d", (int)sts);
    return sts;
  }

  if (license_type == kLicenseTypeRelease) {
    OnKeyReleaseEvent(key_set_id);
  }

  return KEY_MESSAGE;
}

CdmResponseType CdmEngine::AddKey(
    const CdmSessionId& session_id,
    const CdmKeyResponse& key_data,
    CdmKeySetId* key_set_id) {
  LOGI("CdmEngine::AddKey");

  CdmSessionId id = session_id;
  bool license_type_release = session_id.empty();

  if (license_type_release) {
    if (!key_set_id) {
      LOGE("CdmEngine::AddKey: no key set id provided");
      return KEY_ERROR;
    }

    if (key_set_id->empty()) {
      LOGE("CdmEngine::AddKey: invalid key set id");
      return KEY_ERROR;
    }

    CdmReleaseKeySetMap::iterator iter = release_key_sets_.find(*key_set_id);
    if (iter == release_key_sets_.end()) {
      LOGE("CdmEngine::AddKey: key set id not found = %s", key_set_id->c_str());
      return KEY_ERROR;
    }

    id = iter->second;
  }

  CdmSessionMap::iterator iter = sessions_.find(id);

  if (iter == sessions_.end()) {
    LOGE("CdmEngine::AddKey: session id not found = %s", id.c_str());
    return KEY_ERROR;
  }

  if (key_data.empty()) {
    LOGE("CdmEngine::AddKey: no key_data");
    return KEY_ERROR;
  }

  CdmResponseType sts = iter->second->AddKey(key_data, key_set_id);

  if (KEY_ADDED != sts) {
    LOGE("CdmEngine::AddKey: keys not added, result = %d", (int)sts);
    return sts;
  }

  if (!license_type_release) {
    EnablePolicyTimer();
  }

  return KEY_ADDED;
}

CdmResponseType CdmEngine::RestoreKey(
    const CdmSessionId& session_id,
    const CdmKeySetId& key_set_id) {
  LOGI("CdmEngine::RestoreKey");

  if (key_set_id.empty()) {
    LOGI("CdmEngine::RestoreKey: invalid key set id");
    return KEY_ERROR;
  }

  CdmSessionMap::iterator iter = sessions_.find(session_id);
  if (iter == sessions_.end()) {
    LOGE("CdmEngine::RestoreKey: session_id not found = %s ",
        session_id.c_str());
    return UNKNOWN_ERROR;
  }

  CdmResponseType sts =
      iter->second->RestoreOfflineSession(key_set_id, kLicenseTypeOffline);
  if (sts == NEED_PROVISIONING) {
    cert_provisioning_requested_security_level_ =
        iter->second->GetRequestedSecurityLevel();
  }
  return sts;
}

CdmResponseType CdmEngine::CancelKeyRequest(const CdmSessionId& session_id) {
  LOGI("CdmEngine::CancelKeyRequest");

  //TODO(gmorgan): Issue: what is semantics of canceling a key request. Should
  //this call cancel all keys for the session?
  // TODO(jfore): We should disable the policy timer here if there are no
  // active sessions. Sessions are currently not being destroyed here. We can
  // add this logic once the semantics of canceling the key is worked out.

  CdmSessionMap::iterator iter = sessions_.find(session_id);
  if (iter == sessions_.end()) {
    LOGE("CdmEngine::CancelKeyRequest: session_id not found = %s", session_id.c_str());
    return KEY_ERROR;
  }

  // TODO(edwinwong, rfrias): unload keys here
  DisablePolicyTimer(false);
  return NO_ERROR;
}

CdmResponseType CdmEngine::GenerateRenewalRequest(
    const CdmSessionId& session_id,
    CdmKeyMessage* key_request,
    std::string* server_url) {
  LOGI("CdmEngine::GenerateRenewalRequest");

  CdmSessionMap::iterator iter = sessions_.find(session_id);
  if (iter == sessions_.end()) {
    LOGE("CdmEngine::GenerateRenewalRequest: session_id not found = %s", session_id.c_str());
    return KEY_ERROR;
  }

  if (!key_request) {
    LOGE("CdmEngine::GenerateRenewalRequest: no key request destination provided");
    return KEY_ERROR;
  }

  key_request->clear();

  CdmResponseType sts = iter->second->GenerateRenewalRequest(key_request,
                                                             server_url);

  if (KEY_MESSAGE != sts) {
    LOGE("CdmEngine::GenerateRenewalRequest: key request generation failed, sts=%d",
         (int)sts);
    return sts;
  }

  return KEY_MESSAGE;
}

CdmResponseType CdmEngine::RenewKey(
    const CdmSessionId& session_id,
    const CdmKeyResponse& key_data) {
  LOGI("CdmEngine::RenewKey");

  CdmSessionMap::iterator iter = sessions_.find(session_id);
  if (iter == sessions_.end()) {
    LOGE("CdmEngine::RenewKey: session_id not found = %s", session_id.c_str());
    return KEY_ERROR;
  }

  if (key_data.empty()) {
    LOGE("CdmEngine::RenewKey: no key_data");
    return KEY_ERROR;
  }

  CdmResponseType sts = iter->second->RenewKey(key_data);
  if (KEY_ADDED != sts) {
    LOGE("CdmEngine::RenewKey: keys not added, sts=%d", (int)sts);
    return sts;
  }

  return KEY_ADDED;
}

CdmResponseType CdmEngine::QueryStatus(CdmQueryMap* key_info) {
  LOGI("CdmEngine::QueryStatus");
  CryptoSession crypto_session;
  switch (crypto_session.GetSecurityLevel()) {
    case kSecurityLevelL1:
      (*key_info)[QUERY_KEY_SECURITY_LEVEL] = QUERY_VALUE_SECURITY_LEVEL_L1;
      break;
    case kSecurityLevelL2:
      (*key_info)[QUERY_KEY_SECURITY_LEVEL] = QUERY_VALUE_SECURITY_LEVEL_L2;
      break;
    case kSecurityLevelL3:
      (*key_info)[QUERY_KEY_SECURITY_LEVEL] = QUERY_VALUE_SECURITY_LEVEL_L3;
      break;
    case kSecurityLevelUninitialized:
    case kSecurityLevelUnknown:
      (*key_info)[QUERY_KEY_SECURITY_LEVEL] = QUERY_VALUE_SECURITY_LEVEL_Unknown;
      break;
    default:
      return KEY_ERROR;
  }

  std::string deviceId;
  bool success = crypto_session.GetDeviceUniqueId(&deviceId);
  if (success) {
    (*key_info)[QUERY_KEY_DEVICE_ID] = deviceId;
  }

  uint32_t system_id;
  success = crypto_session.GetSystemId(&system_id);
  if (success) {
    std::ostringstream system_id_stream;
    system_id_stream << system_id;
    (*key_info)[QUERY_KEY_SYSTEM_ID] = system_id_stream.str();
  }

  std::string provisioning_id;
  success = crypto_session.GetProvisioningId(&provisioning_id);
  if (success) {
    (*key_info)[QUERY_KEY_PROVISIONING_ID] = provisioning_id;
  }

  return NO_ERROR;
}

CdmResponseType CdmEngine::QuerySessionStatus(const CdmSessionId& session_id,
                                              CdmQueryMap* key_info) {
  LOGI("CdmEngine::QuerySessionStatus");
  CdmSessionMap::iterator iter = sessions_.find(session_id);
  if (iter == sessions_.end()) {
    LOGE("CdmEngine::QuerySessionStatus: session_id not found = %s",
         session_id.c_str());
    return KEY_ERROR;
  }
  return iter->second->QueryStatus(key_info);
}

CdmResponseType CdmEngine::QueryKeyStatus(
    const CdmSessionId& session_id,
    CdmQueryMap* key_info) {
  LOGI("CdmEngine::QueryKeyStatus");
  CdmSessionMap::iterator iter = sessions_.find(session_id);
  if (iter == sessions_.end()) {
    LOGE("CdmEngine::QueryKeyStatus: session_id not found = %s", session_id.c_str());
    return KEY_ERROR;
  }
  return iter->second->QueryKeyStatus(key_info);
}

CdmResponseType CdmEngine::QueryKeyControlInfo(
    const CdmSessionId& session_id,
    CdmQueryMap* key_info) {
  LOGI("CdmEngine::QueryKeyControlInfo");
  CdmSessionMap::iterator iter = sessions_.find(session_id);
  if (iter == sessions_.end()) {
    LOGE("CdmEngine::QueryKeyControlInfo: session_id not found = %s", session_id.c_str());
    return KEY_ERROR;
  }
  return iter->second->QueryKeyControlInfo(key_info);
}

/*
 * Composes a device provisioning request and output the request in JSON format
 * in *request. It also returns the default url for the provisioning server
 * in *default_url.
 *
 * Returns NO_ERROR for success and UNKNOWN_ERROR if fails.
 */
CdmResponseType CdmEngine::GetProvisioningRequest(
    CdmProvisioningRequest* request,
    std::string* default_url) {
  if (!request || !default_url) {
    LOGE("CdmEngine::GetProvisioningRequest: invalid input parameters");
    return UNKNOWN_ERROR;
  }
  return cert_provisioning_.GetProvisioningRequest(
             cert_provisioning_requested_security_level_,
             request,
             default_url);
}

/*
 * The response message consists of a device certificate and the device RSA key.
 * The device RSA key is stored in the T.E.E. The device certificate is stored
 * in the device.
 *
 * Returns NO_ERROR for success and UNKNOWN_ERROR if fails.
 */
CdmResponseType CdmEngine::HandleProvisioningResponse(
    CdmProvisioningResponse& response) {
  if (response.empty()) {
    LOGE("CdmEngine::HandleProvisioningResponse: Empty provisioning response.");
    return UNKNOWN_ERROR;
  }
  return cert_provisioning_.HandleProvisioningResponse(response);
}

CdmResponseType CdmEngine::GetSecureStops(
    CdmSecureStops* secure_stops) {
  // TODO(edwinwong, rfrias): add implementation
  return NO_ERROR;
}

CdmResponseType CdmEngine::ReleaseSecureStops(
    const CdmSecureStopReleaseMessage& message) {
  // TODO(edwinwong, rfrias): add implementation
  return NO_ERROR;
}

CdmResponseType CdmEngine::Decrypt(
    const CdmSessionId& session_id,
    const CdmDecryptionParameters& parameters) {
  if (parameters.key_id == NULL) {
    LOGE("CdmEngine::Decrypt: no key_id");
    return KEY_ERROR;
  }

  if (parameters.encrypt_buffer == NULL) {
    LOGE("CdmEngine::Decrypt: no src encrypt buffer");
    return KEY_ERROR;
  }

  if (parameters.iv == NULL) {
    LOGE("CdmEngine::Decrypt: no iv");
    return KEY_ERROR;
  }

  if (parameters.decrypt_buffer == NULL) {
    LOGE("CdmEngine::Decrypt: no dest decrypt buffer");
    return KEY_ERROR;
  }

  CdmSessionMap::iterator iter;
  if (session_id.empty()) {
    if (!Properties::decrypt_with_empty_session_support()) return KEY_ERROR;

    // Loop through the sessions to find the session containing the key_id.
    for (iter = sessions_.begin(); iter != sessions_.end(); ++iter) {
      if (iter->second->IsKeyValid(*parameters.key_id)) break;
    }
  } else {
    iter = sessions_.find(session_id);
  }
  if (iter == sessions_.end()) {
    LOGE("CdmEngine::Decrypt: session_id not found = %s", session_id.c_str());
    return KEY_ERROR;
  }

  return iter->second->Decrypt(parameters);
}

bool CdmEngine::IsKeyValid(const KeyId& key_id) {
  for (CdmSessionMap::iterator iter = sessions_.begin();
       iter != sessions_.end(); ++iter) {
    if (iter->second->IsKeyValid(key_id)) {
      return true;
    }
  }
  return false;
}

bool CdmEngine::FindSessionForKey(
    const KeyId& key_id,
    CdmSessionId* session_id) {
  if (NULL == session_id) {
    LOGE("CdmEngine::FindSessionForKey: session id not provided");
    return false;
  }

  uint32_t session_sharing_id = Properties::GetSessionSharingId(*session_id);

  for (CdmSessionMap::iterator iter = sessions_.begin();
       iter != sessions_.end(); ++iter) {
    CdmSessionId id = iter->second->session_id();
    if (Properties::GetSessionSharingId(id) == session_sharing_id) {
      if (iter->second->IsKeyValid(key_id)) {
        *session_id = id;
        return true;
      }
    }
  }
  return false;
}

bool CdmEngine::AttachEventListener(
    const CdmSessionId& session_id,
    WvCdmEventListener* listener) {

  CdmSessionMap::iterator iter = sessions_.find(session_id);
  if (iter == sessions_.end()) {
    return false;
  }

  return iter->second->AttachEventListener(listener);
}

bool CdmEngine::DetachEventListener(
    const CdmSessionId& session_id,
    WvCdmEventListener* listener) {

  CdmSessionMap::iterator iter = sessions_.find(session_id);
  if (iter == sessions_.end()) {
    return false;
  }

  return iter->second->DetachEventListener(listener);
}

bool CdmEngine::ValidateKeySystem(const CdmKeySystem& key_system) {
  return (key_system.find("widevine") != std::string::npos);
}

bool CdmEngine::CancelSessions() {
  // TODO(gmorgan) Implement CancelSessions()
  return true;
}

// Parse a blob of multiple concatenated PSSH atoms to extract the first
// widevine pssh
// TODO(kqyang): temporary workaround - remove after b/7928472 is resolved
bool CdmEngine::ExtractWidevinePssh(
    const CdmInitData& init_data, CdmInitData* output) {

  BufferReader reader(
      reinterpret_cast<const uint8_t*>(init_data.data()), init_data.length());

  // TODO(kqyang): Extracted from an actual init_data;
  // Need to find out where it comes from.
  static const uint8_t kWidevineSystemId[] = {
      0xED, 0xEF, 0x8B, 0xA9, 0x79, 0xD6, 0x4A, 0xCE,
      0xA3, 0xC8, 0x27, 0xDC, 0xD5, 0x1D, 0x21, 0xED,
  };

  // one PSSH blob consists of:
  // 4 byte size of the PSSH atom, inclusive
  // "pssh"
  // 4 byte flags, value 0
  // 16 byte system id
  // 4 byte size of PSSH data, exclusive
  while (1) {
    // size of PSSH atom, used for skipping
    uint32_t size;
    if (!reader.Read4(&size)) {
      LOGW("CdmEngine::ExtractWidevinePssh: Unable to read PSSH atom size");
      return false;
    }

    // "pssh"
    std::vector<uint8_t> pssh;
    if (!reader.ReadVec(&pssh, 4)) {
      LOGW("CdmEngine::ExtractWidevinePssh: Unable to read PSSH literal");
      return false;
    }
    if (memcmp(&pssh[0], "pssh", 4)) {
      LOGW("CdmEngine::ExtractWidevinePssh: PSSH literal not present");
      return false;
    }

    // flags
    uint32_t flags;
    if (!reader.Read4(&flags)) {
      LOGW("CdmEngine::ExtractWidevinePssh: Unable to read PSSH flags");
      return false;
    }
    if (flags != 0) {
      LOGW("CdmEngine::ExtractWidevinePssh: PSSH flags not zero");
      return false;
    }

    // system id
    std::vector<uint8_t> system_id;
    if (!reader.ReadVec(&system_id, sizeof(kWidevineSystemId))) {
      LOGW("CdmEngine::ExtractWidevinePssh: Unable to read system ID");
      return false;
    }

    if (memcmp(&system_id[0], kWidevineSystemId,
               sizeof(kWidevineSystemId))) {
      // skip the remaining contents of the atom,
      // after size field, atom name, flags and system id
      if (!reader.SkipBytes(
          size - 4 - 4 - 4 - sizeof(kWidevineSystemId))) {
        LOGW("CdmEngine::ExtractWidevinePssh: Unable to rest of PSSH atom");
        return false;
      }
      continue;
    }

    // size of PSSH box
    uint32_t pssh_length;
    if (!reader.Read4(&pssh_length)) {
      LOGW("CdmEngine::ExtractWidevinePssh: Unable to read PSSH box size");
      return false;
    }

    output->clear();
    if (!reader.ReadString(output, pssh_length)) {
      LOGW("CdmEngine::ExtractWidevinePssh: Unable to read PSSH");
      return false;
    }

    return true;
  }

  // we did not find a matching record
  return false;
}

void CdmEngine::EnablePolicyTimer() {
  if (!policy_timer_.IsRunning())
    policy_timer_.Start(this, kCdmPolicyTimerDurationSeconds);
}

void CdmEngine::DisablePolicyTimer(bool force) {
  if ((sessions_.size() == 0 || force) && policy_timer_.IsRunning())
    policy_timer_.Stop();
}

void CdmEngine::OnTimerEvent() {
  for (CdmSessionMap::iterator iter = sessions_.begin();
       iter != sessions_.end(); ++iter) {
    iter->second->OnTimerEvent();
  }
}

void CdmEngine::OnKeyReleaseEvent(const CdmKeySetId& key_set_id) {

  for (CdmSessionMap::iterator iter = sessions_.begin();
       iter != sessions_.end(); ++iter) {
    iter->second->OnKeyReleaseEvent(key_set_id);
  }
}

}  // namespace wvcdm
