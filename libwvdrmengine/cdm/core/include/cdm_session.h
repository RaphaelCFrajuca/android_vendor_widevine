// Copyright 2012 Google Inc. All Rights Reserved.

#ifndef CDM_BASE_CDM_SESSION_H_
#define CDM_BASE_CDM_SESSION_H_

#include <set>

#include "crypto_session.h"
#include "device_files.h"
#include "license.h"
#include "oemcrypto_adapter.h"
#include "policy_engine.h"
#include "scoped_ptr.h"
#include "wv_cdm_types.h"

namespace wvcdm {

class CdmClientPropertySet;
class WvCdmEventListener;

class CdmSession {
 public:
  explicit CdmSession(const CdmClientPropertySet* cdm_client_property_set);
  ~CdmSession();

  CdmResponseType Init();

  CdmResponseType RestoreOfflineSession(const CdmKeySetId& key_set_id,
                                        const CdmLicenseType license_type);

  void set_key_system(const CdmKeySystem& ksystem) { key_system_ = ksystem; }
  const CdmKeySystem& key_system() { return key_system_; }

  const CdmSessionId& session_id() { return session_id_; }

  bool VerifySession(const CdmKeySystem& key_system,
                     const CdmInitData& init_data);

  CdmResponseType GenerateKeyRequest(const CdmInitData& init_data,
                                     const CdmLicenseType license_type,
                                     const CdmAppParameterMap& app_parameters,
                                     CdmKeyMessage* key_request,
                                     std::string* server_url);

  // AddKey() - Accept license response and extract key info.
  CdmResponseType AddKey(const CdmKeyResponse& key_response,
                         CdmKeySetId* key_set_id);

  // CancelKeyRequest() - Cancel session.
  CdmResponseType CancelKeyRequest();

  // Query session status
  CdmResponseType QueryStatus(CdmQueryMap* key_info);

  // Query license information
  CdmResponseType QueryKeyStatus(CdmQueryMap* key_info);

  // Query session control info
  CdmResponseType QueryKeyControlInfo(CdmQueryMap* key_info);

  // Decrypt() - Accept encrypted buffer and return decrypted data.
  CdmResponseType Decrypt(const CdmDecryptionParameters& parameters);

  // License renewal
  // GenerateRenewalRequest() - Construct valid renewal request for the current
  // session keys.
  CdmResponseType GenerateRenewalRequest(CdmKeyMessage* key_request,
                                         std::string* server_url);

  // RenewKey() - Accept renewal response and update key info.
  CdmResponseType RenewKey(const CdmKeyResponse& key_response);

  // License release
  // GenerateReleaseRequest() - Construct valid release request for the current
  // session keys.
  CdmResponseType GenerateReleaseRequest(CdmKeyMessage* key_request,
                                         std::string* server_url);

  // ReleaseKey() - Accept response and release key.
  CdmResponseType ReleaseKey(const CdmKeyResponse& key_response);

  bool IsKeyValid(const KeyId& key_id);

  bool AttachEventListener(WvCdmEventListener* listener);
  bool DetachEventListener(WvCdmEventListener* listener);

  void OnTimerEvent();
  void OnKeyReleaseEvent(const CdmKeySetId& key_set_id);

  SecurityLevel GetRequestedSecurityLevel();

 private:

  // Generate unique ID for each new session.
  CdmSessionId GenerateSessionId();
  bool GenerateKeySetId(CdmKeySetId* key_set_id);

  bool StoreLicense(DeviceFiles::LicenseState state);

  // instance variables
  const CdmSessionId session_id_;
  CdmKeySystem key_system_;
  CdmLicense license_parser_;
  scoped_ptr<CryptoSession> crypto_session_;
  PolicyEngine policy_engine_;
  bool license_received_;
  bool reinitialize_session_;

  CdmLicenseType license_type_;

  // license type offline related information
  CdmInitData offline_pssh_data_;
  CdmKeyMessage offline_key_request_;
  CdmKeyResponse offline_key_response_;
  CdmKeyMessage offline_key_renewal_request_;
  CdmKeyResponse offline_key_renewal_response_;
  std::string offline_release_server_url_;

  // license type release and offline related information
  CdmKeySetId key_set_id_;

  KeyId key_id_;

  // Used for certificate based licensing
  std::string wrapped_key_;
  bool is_certificate_loaded_;

  std::set<WvCdmEventListener*> listeners_;

  CORE_DISALLOW_COPY_AND_ASSIGN(CdmSession);
};

}  // namespace wvcdm

#endif  // CDM_BASE_CDM_SESSION_H_
