// Copyright 2013 Google Inc. All Rights Reserved.

#include "wv_content_decryption_module.h"

#include <iostream>

#include "cdm_client_property_set.h"
#include "cdm_engine.h"
#include "log.h"
#include "properties.h"
#include "wv_cdm_constants.h"
#include "wv_cdm_event_listener.h"

namespace wvcdm {

WvContentDecryptionModule::WvContentDecryptionModule()
    : cdm_engine_(new CdmEngine()) {}

WvContentDecryptionModule::~WvContentDecryptionModule() {}

CdmResponseType WvContentDecryptionModule::OpenSession(
    const CdmKeySystem& key_system,
    CdmClientPropertySet* property_set,
    CdmSessionId* session_id) {
  if (property_set && property_set->is_session_sharing_enabled()) {
    if (property_set->session_sharing_id() == 0)
      property_set->set_session_sharing_id(GenerateSessionSharingId());
  }

  return cdm_engine_->OpenSession(key_system, property_set, session_id);
}

CdmResponseType WvContentDecryptionModule::CloseSession(
    const CdmSessionId& session_id) {
  return cdm_engine_->CloseSession(session_id);
}

CdmResponseType WvContentDecryptionModule::GenerateKeyRequest(
    const CdmSessionId& session_id,
    const CdmKeySetId& key_set_id,
    const CdmInitData& init_data,
    const CdmLicenseType license_type,
    CdmAppParameterMap& app_parameters,
    CdmKeyMessage* key_request,
    std::string* server_url) {
  CdmResponseType sts;
  if (license_type == kLicenseTypeRelease) {
      sts = cdm_engine_->OpenKeySetSession(key_set_id);
      if (sts != NO_ERROR)
        return sts;
  }
  sts = cdm_engine_->GenerateKeyRequest(session_id, key_set_id,
                                        init_data, license_type,
                                        app_parameters, key_request,
                                        server_url);

  if (license_type == kLicenseTypeRelease && sts != KEY_MESSAGE) {
    cdm_engine_->CloseKeySetSession(key_set_id);
  }
  return sts;
}

CdmResponseType WvContentDecryptionModule::AddKey(
    const CdmSessionId& session_id,
    const CdmKeyResponse& key_data,
    CdmKeySetId* key_set_id) {
  CdmResponseType sts = cdm_engine_->AddKey(session_id, key_data, key_set_id);
  if (sts == KEY_ADDED && session_id.empty())   // license type release
    cdm_engine_->CloseKeySetSession(*key_set_id);
  return sts;
}

CdmResponseType WvContentDecryptionModule::RestoreKey(
    const CdmSessionId& session_id,
    const CdmKeySetId& key_set_id) {
  return cdm_engine_->RestoreKey(session_id, key_set_id);
}

CdmResponseType WvContentDecryptionModule::CancelKeyRequest(
    const CdmSessionId& session_id) {
  return cdm_engine_->CancelKeyRequest(session_id);
}

CdmResponseType WvContentDecryptionModule::QueryStatus(CdmQueryMap* key_info) {
  return cdm_engine_->QueryStatus(key_info);
}

CdmResponseType WvContentDecryptionModule::QuerySessionStatus(
    const CdmSessionId& session_id, CdmQueryMap* key_info) {
  return cdm_engine_->QuerySessionStatus(session_id, key_info);
}

CdmResponseType WvContentDecryptionModule::QueryKeyStatus(
    const CdmSessionId& session_id, CdmQueryMap* key_info) {
  return cdm_engine_->QueryKeyStatus(session_id, key_info);
}

CdmResponseType WvContentDecryptionModule::QueryKeyControlInfo(
    const CdmSessionId& session_id, CdmQueryMap* key_info) {
  return cdm_engine_->QueryKeyControlInfo(session_id, key_info);
}

CdmResponseType WvContentDecryptionModule::GetProvisioningRequest(
    CdmProvisioningRequest* request, std::string* default_url) {
  return cdm_engine_->GetProvisioningRequest(request, default_url);
}

CdmResponseType WvContentDecryptionModule::HandleProvisioningResponse(
    CdmProvisioningResponse& response) {
  return cdm_engine_->HandleProvisioningResponse(response);
}

CdmResponseType WvContentDecryptionModule::GetSecureStops(
    CdmSecureStops* secure_stops) {
  return cdm_engine_->GetSecureStops(secure_stops);
}

CdmResponseType WvContentDecryptionModule::ReleaseSecureStops(
    const CdmSecureStopReleaseMessage& message) {
  return cdm_engine_->ReleaseSecureStops(message);
}

CdmResponseType WvContentDecryptionModule::Decrypt(
    const CdmSessionId& session_id,
    const CdmDecryptionParameters& parameters) {
  CdmSessionId id = session_id;
  if (parameters.is_encrypted &&
      Properties::GetSessionSharingId(session_id) != 0) {
    bool status = cdm_engine_->FindSessionForKey(*parameters.key_id, &id);
    if (!status) {
      LOGE("WvContentDecryptionModule::Decrypt: unable to find session");
      return NEED_KEY;
    }
  }
  return cdm_engine_->Decrypt(id, parameters);
}

bool WvContentDecryptionModule::AttachEventListener(
    const CdmSessionId& session_id, WvCdmEventListener* listener) {
  return cdm_engine_->AttachEventListener(session_id, listener);
}

bool WvContentDecryptionModule::DetachEventListener(
    const CdmSessionId& session_id, WvCdmEventListener* listener) {
  return cdm_engine_->DetachEventListener(session_id, listener);
}

uint32_t WvContentDecryptionModule::GenerateSessionSharingId() {
  static int next_session_sharing_id = 0;
  return ++next_session_sharing_id;
}

}  // namespace wvcdm
