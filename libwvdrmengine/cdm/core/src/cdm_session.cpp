// Copyright 2012 Google Inc. All Rights Reserved.
// Author: jfore@google.com (Jeff Fore), rkuroiwa@google.com (Rintaro Kuroiwa)

#include "cdm_session.h"

#include <iostream>
#include <sstream>
#include <stdlib.h>

#include "cdm_engine.h"
#include "clock.h"
#include "crypto_session.h"
#include "device_files.h"
#include "file_store.h"
#include "log.h"
#include "properties.h"
#include "string_conversions.h"
#include "wv_cdm_constants.h"
#include "wv_cdm_event_listener.h"

namespace {
const size_t kKeySetIdLength = 14;
}  // namespace

namespace wvcdm {

typedef std::set<WvCdmEventListener*>::iterator CdmEventListenerIter;

CdmSession::CdmSession(const CdmClientPropertySet* cdm_client_property_set)
    : session_id_(GenerateSessionId()),
      crypto_session_(NULL),
      license_received_(false),
      reinitialize_session_(false),
      license_type_(kLicenseTypeStreaming),
      is_certificate_loaded_(false) {
  if (cdm_client_property_set) {
    Properties::AddSessionPropertySet(session_id_, cdm_client_property_set);
  }
}

CdmSession::~CdmSession() { Properties::RemoveSessionPropertySet(session_id_); }

CdmResponseType CdmSession::Init() {
  scoped_ptr<CryptoSession> session(new CryptoSession());

  CdmResponseType sts = session->Open(GetRequestedSecurityLevel());
  if (NO_ERROR != sts) return sts;

  std::string token;
  if (Properties::use_certificates_as_identification()) {
    File file;
    DeviceFiles handle;
    if (!handle.Init(&file, session.get()->GetSecurityLevel()) ||
        !handle.RetrieveCertificate(&token, &wrapped_key_)) {
      return NEED_PROVISIONING;
    }
  } else {
    if (!session->GetToken(&token)) return UNKNOWN_ERROR;
  }

  if (!license_parser_.Init(token, session.get(), &policy_engine_))
    return UNKNOWN_ERROR;

  crypto_session_.reset(session.release());
  license_received_ = false;
  reinitialize_session_ = false;
  return NO_ERROR;
}

CdmResponseType CdmSession::RestoreOfflineSession(
    const CdmKeySetId& key_set_id, const CdmLicenseType license_type) {
  key_set_id_ = key_set_id;

  // Retrieve license information from persistent store
  File file;
  DeviceFiles handle;
  if (!handle.Init(&file, crypto_session_->GetSecurityLevel()))
    return UNKNOWN_ERROR;

  DeviceFiles::LicenseState license_state;

  if (!handle.RetrieveLicense(key_set_id, &license_state, &offline_pssh_data_,
                              &offline_key_request_, &offline_key_response_,
                              &offline_key_renewal_request_,
                              &offline_key_renewal_response_,
                              &offline_release_server_url_)) {
    LOGE("CdmSession::Init failed to retrieve license. key set id = %s",
         key_set_id.c_str());
    return UNKNOWN_ERROR;
  }

  if (license_state != DeviceFiles::kLicenseStateActive) {
    LOGE("CdmSession::Init invalid offline license state = %s", license_state);
    return UNKNOWN_ERROR;
  }

  if (Properties::use_certificates_as_identification()) {
    if (!crypto_session_->LoadCertificatePrivateKey(wrapped_key_)) {
      return NEED_PROVISIONING;
    }
  }

  if (!license_parser_.RestoreOfflineLicense(offline_key_request_,
                                             offline_key_response_,
                                             offline_key_renewal_response_)) {
    return UNKNOWN_ERROR;
  }

  license_received_ = true;
  license_type_ = license_type;
  return KEY_ADDED;
}

bool CdmSession::VerifySession(const CdmKeySystem& key_system,
                               const CdmInitData& init_data) {
  // TODO(gmorgan): Compare key_system and init_data with value received
  // during session startup - they should be the same.
  return true;
}

CdmResponseType CdmSession::GenerateKeyRequest(
    const CdmInitData& init_data, const CdmLicenseType license_type,
    const CdmAppParameterMap& app_parameters, CdmKeyMessage* key_request,
    std::string* server_url) {
  if (reinitialize_session_) {
    CdmResponseType sts = Init();
    if (sts != NO_ERROR) {
      LOGW("CdmSession::GenerateKeyRequest: Reinitialization failed");
      return sts;
    }
  }

  if (crypto_session_.get() == NULL) {
    LOGW("CdmSession::GenerateKeyRequest: Invalid crypto session");
    return UNKNOWN_ERROR;
  }

  if (!crypto_session_->IsOpen()) {
    LOGW("CdmSession::GenerateKeyRequest: Crypto session not open");
    return UNKNOWN_ERROR;
  }

  license_type_ = license_type;

  if (license_type_ == kLicenseTypeRelease) {
    return GenerateReleaseRequest(key_request, server_url);
  } else if (license_received_) {  // renewal
    return Properties::require_explicit_renew_request()
               ? UNKNOWN_ERROR
               : GenerateRenewalRequest(key_request, server_url);
  } else {
    if (init_data.empty() && !license_parser_.HasInitData()) {
      LOGW("CdmSession::GenerateKeyRequest: init data absent");
      return KEY_ERROR;
    }

    CdmInitData pssh_data = init_data;
    if (Properties::extract_pssh_data()) {
      if (!CdmEngine::ExtractWidevinePssh(init_data, &pssh_data)) {
        return KEY_ERROR;
      }
    }

    if (Properties::use_certificates_as_identification()) {
      if (is_certificate_loaded_ ||
          crypto_session_->LoadCertificatePrivateKey(wrapped_key_)) {
        is_certificate_loaded_ = true;
      }
      else {
        reinitialize_session_ = true;
        return NEED_PROVISIONING;
      }
    }

    if (!license_parser_.PrepareKeyRequest(pssh_data, license_type,
                                           app_parameters, session_id_,
                                           key_request, server_url)) {
      return KEY_ERROR;
    }

    if (license_type_ == kLicenseTypeOffline) {
      offline_pssh_data_ = pssh_data;
      offline_key_request_ = *key_request;
      offline_release_server_url_ = *server_url;
    }

    return KEY_MESSAGE;
  }
}

// AddKey() - Accept license response and extract key info.
CdmResponseType CdmSession::AddKey(const CdmKeyResponse& key_response,
                                   CdmKeySetId* key_set_id) {
  if (crypto_session_.get() == NULL) {
    LOGW("CdmSession::AddKey: Invalid crypto session");
    return UNKNOWN_ERROR;
  }

  if (!crypto_session_->IsOpen()) {
    LOGW("CdmSession::AddKey: Crypto session not open");
    return UNKNOWN_ERROR;
  }

  if (license_type_ == kLicenseTypeRelease) {
    return ReleaseKey(key_response);
  } else if (license_received_) {  // renewal
    return Properties::require_explicit_renew_request()
               ? UNKNOWN_ERROR
               : RenewKey(key_response);
  } else {
    CdmResponseType sts = license_parser_.HandleKeyResponse(key_response);

    if (sts != KEY_ADDED) return sts;

    license_received_ = true;

    if (license_type_ == kLicenseTypeOffline) {
      offline_key_response_ = key_response;
      if (!GenerateKeySetId(&key_set_id_)) {
        LOGE("CdmSession::AddKey: Unable to generate key set Id");
        return UNKNOWN_ERROR;
      }

      if (!StoreLicense(DeviceFiles::kLicenseStateActive)) {
        LOGE("CdmSession::AddKey: Unable to store license");
        CdmResponseType sts = Init();
        if (sts != NO_ERROR) {
          LOGW("CdmSession::AddKey: Reinitialization failed");
          return sts;
        }

        key_set_id_.clear();
        return UNKNOWN_ERROR;
      }
    }

    *key_set_id = key_set_id_;
    return KEY_ADDED;
  }
}

CdmResponseType CdmSession::QueryStatus(CdmQueryMap* key_info) {
  if (crypto_session_.get() == NULL) {
    LOGW("CdmSession::QueryStatus: Invalid crypto session");
    return UNKNOWN_ERROR;
  }

  if (!crypto_session_->IsOpen()) {
    LOGW("CdmSession::QueryStatus: Crypto session not open");
    return UNKNOWN_ERROR;
  }

  switch (crypto_session_->GetSecurityLevel()) {
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
  return NO_ERROR;
}

CdmResponseType CdmSession::QueryKeyStatus(CdmQueryMap* key_info) {
  return policy_engine_.Query(key_info);
}

CdmResponseType CdmSession::QueryKeyControlInfo(CdmQueryMap* key_info) {
  if (crypto_session_.get() == NULL) {
    LOGW("CdmSession::QueryKeyControlInfo: Invalid crypto session");
    return UNKNOWN_ERROR;
  }

  if (!crypto_session_->IsOpen()) {
    LOGW("CdmSession::QueryKeyControlInfo: Crypto session not open");
    return UNKNOWN_ERROR;
  }

  std::stringstream ss;
  ss << crypto_session_->oec_session_id();
  (*key_info)[QUERY_KEY_OEMCRYPTO_SESSION_ID] = ss.str();
  return NO_ERROR;
}

// CancelKeyRequest() - Cancel session.
CdmResponseType CdmSession::CancelKeyRequest() {
  // TODO(gmorgan): cancel and clean up session
  crypto_session_->Close();
  return NO_ERROR;
}

// Decrypt() - Accept encrypted buffer and return decrypted data.
CdmResponseType CdmSession::Decrypt(const CdmDecryptionParameters& params) {
  if (crypto_session_.get() == NULL || !crypto_session_->IsOpen())
    return UNKNOWN_ERROR;

  CdmResponseType status = crypto_session_->Decrypt(params);
  // TODO(rfrias): Remove after support for OEMCrypto_ERROR_KEY_EXPIRED is in
  if (UNKNOWN_ERROR == status) {
    Clock clock;
    int64_t current_time = clock.GetCurrentTime();
    if (policy_engine_.IsLicenseDurationExpired(current_time) ||
        policy_engine_.IsPlaybackDurationExpired(current_time)) {
      return NEED_KEY;
    }
  }
  return status;
}

// License renewal
// GenerateRenewalRequest() - Construct valid renewal request for the current
// session keys.
CdmResponseType CdmSession::GenerateRenewalRequest(CdmKeyMessage* key_request,
                                                   std::string* server_url) {
  if (!license_parser_.PrepareKeyUpdateRequest(true, key_request, server_url))
    return KEY_ERROR;

  if (license_type_ == kLicenseTypeOffline) {
    offline_key_renewal_request_ = *key_request;
  }
  return KEY_MESSAGE;
}

// RenewKey() - Accept renewal response and update key info.
CdmResponseType CdmSession::RenewKey(const CdmKeyResponse& key_response) {
  CdmResponseType sts =
      license_parser_.HandleKeyUpdateResponse(true, key_response);
  if (sts != KEY_ADDED) return sts;

  if (license_type_ == kLicenseTypeOffline) {
    offline_key_renewal_response_ = key_response;
    if (!StoreLicense(DeviceFiles::kLicenseStateActive)) return UNKNOWN_ERROR;
  }
  return KEY_ADDED;
}

CdmResponseType CdmSession::GenerateReleaseRequest(CdmKeyMessage* key_request,
                                                   std::string* server_url) {
  if (license_parser_.PrepareKeyUpdateRequest(false, key_request, server_url)) {
    // Mark license as being released
    if (StoreLicense(DeviceFiles::kLicenseStateReleasing)) return KEY_MESSAGE;
  }
  return UNKNOWN_ERROR;
}

// ReleaseKey() - Accept release response and  release license.
CdmResponseType CdmSession::ReleaseKey(const CdmKeyResponse& key_response) {
  CdmResponseType sts =
      license_parser_.HandleKeyUpdateResponse(false, key_response);
  File file;
  DeviceFiles handle;
  if (handle.Init(&file, crypto_session_->GetSecurityLevel()))
    handle.DeleteLicense(key_set_id_);

  return sts;
}

bool CdmSession::IsKeyValid(const KeyId& key_id) {
  return license_parser_.IsKeyLoaded(key_id);
}

CdmSessionId CdmSession::GenerateSessionId() {
  static int session_num = 1;
  // TODO(rkuroiwa): Want this to be unique. Probably doing Hash(time+init_data)
  // to get something that is reasonably unique.
  return SESSION_ID_PREFIX + IntToString(++session_num);
}

bool CdmSession::GenerateKeySetId(CdmKeySetId* key_set_id) {
  if (!key_set_id) {
    LOGW("CdmSession::GenerateKeySetId: key set id destination not provided");
    return false;
  }

  std::vector<uint8_t> random_data(
      (kKeySetIdLength - sizeof(KEY_SET_ID_PREFIX)) / 2, 0);

  File file;
  DeviceFiles handle;
  if (!handle.Init(&file, crypto_session_->GetSecurityLevel()))
    return false;

  while (key_set_id->empty()) {
    if (!crypto_session_->GetRandom(random_data.size(), &random_data[0]))
      return false;

    *key_set_id = KEY_SET_ID_PREFIX + b2a_hex(random_data);

    // key set collision
    if (handle.LicenseExists(*key_set_id)) {
      key_set_id->clear();
    }
  }
  return true;
}

bool CdmSession::StoreLicense(DeviceFiles::LicenseState state) {
  File file;
  DeviceFiles handle;
  if (!handle.Init(&file, crypto_session_->GetSecurityLevel()))
    return false;

  return handle.StoreLicense(
      key_set_id_, state, offline_pssh_data_, offline_key_request_,
      offline_key_response_, offline_key_renewal_request_,
      offline_key_renewal_response_, offline_release_server_url_);
}

bool CdmSession::AttachEventListener(WvCdmEventListener* listener) {
  std::pair<CdmEventListenerIter, bool> result = listeners_.insert(listener);
  return result.second;
}

bool CdmSession::DetachEventListener(WvCdmEventListener* listener) {
  return (listeners_.erase(listener) == 1);
}

void CdmSession::OnTimerEvent() {
  bool event_occurred = false;
  CdmEventType event;

  policy_engine_.OnTimerEvent(event_occurred, event);

  if (event_occurred) {
    for (CdmEventListenerIter iter = listeners_.begin();
         iter != listeners_.end(); ++iter) {
      (*iter)->onEvent(session_id_, event);
    }
  }
}

void CdmSession::OnKeyReleaseEvent(const CdmKeySetId& key_set_id) {
  if (key_set_id_ == key_set_id) {
    for (CdmEventListenerIter iter = listeners_.begin();
         iter != listeners_.end(); ++iter) {
      (*iter)->onEvent(session_id_, LICENSE_EXPIRED_EVENT);
    }
  }
}

SecurityLevel CdmSession::GetRequestedSecurityLevel() {
  if (Properties::GetSecurityLevel(session_id_)
          .compare(QUERY_VALUE_SECURITY_LEVEL_L3) == 0) {
    return kLevel3;
  }

  return kLevelDefault;
}

}  // namespace wvcdm
