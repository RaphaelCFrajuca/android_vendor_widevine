// Copyright 2013 Google Inc. All Rights Reserved.

#ifndef CDM_BASE_CDM_ENGINE_H_
#define CDM_BASE_CDM_ENGINE_H_

#include "certificate_provisioning.h"
#include "oemcrypto_adapter.h"
#include "timer.h"
#include "wv_cdm_types.h"

namespace wvcdm {

class CdmClientPropertySet;
class CdmSession;
class CryptoEngine;
class WvCdmEventListener;

typedef std::map<CdmSessionId, CdmSession*> CdmSessionMap;
typedef std::map<CdmKeySetId, CdmSessionId> CdmReleaseKeySetMap;

class CdmEngine : public TimerHandler {
 public:
  CdmEngine();
  virtual ~CdmEngine();

  // Session related methods
  virtual CdmResponseType OpenSession(
      const CdmKeySystem& key_system,
      const CdmClientPropertySet* property_set,
      CdmSessionId* session_id);
  virtual CdmResponseType CloseSession(const CdmSessionId& session_id);

  virtual CdmResponseType OpenKeySetSession(const CdmKeySetId& key_set_id);
  virtual CdmResponseType CloseKeySetSession(const CdmKeySetId& key_set_id);

  // License related methods
  // Construct a valid license request
  virtual CdmResponseType GenerateKeyRequest(const CdmSessionId& session_id,
                                             const CdmKeySetId& key_set_id,
                                             const CdmInitData& init_data,
                                             const CdmLicenseType license_type,
                                             CdmAppParameterMap& app_parameters,
                                             CdmKeyMessage* key_request,
                                             std::string* server_url);

  // Accept license response and extract key info.
  virtual CdmResponseType AddKey(const CdmSessionId& session_id,
                                 const CdmKeyResponse& key_data,
                                 CdmKeySetId* key_set_id);

  virtual CdmResponseType RestoreKey(const CdmSessionId& session_id,
                                     const CdmKeySetId& key_set_id);

  CdmResponseType CancelKeyRequest(const CdmSessionId& session_id);

  // Construct valid renewal request for the current session keys.
  virtual CdmResponseType GenerateRenewalRequest(const CdmSessionId& session_id,
                                                 CdmKeyMessage* key_request,
                                                 std::string* server_url);

  // Accept renewal response and update key info.
  virtual CdmResponseType RenewKey(const CdmSessionId& session_id,
                                   const CdmKeyResponse& key_data);

  // Query system information
  virtual CdmResponseType QueryStatus(CdmQueryMap* info);

  // Query session information
  virtual CdmResponseType QuerySessionStatus(const CdmSessionId& session_id,
                                             CdmQueryMap* key_info);

  // Query license information
  virtual CdmResponseType QueryKeyStatus(const CdmSessionId& session_id,
                                         CdmQueryMap* key_info);

  // Query seesion control information
  virtual CdmResponseType QueryKeyControlInfo(const CdmSessionId& session_id,
                                              CdmQueryMap* key_info);

  // Provisioning related methods
  virtual CdmResponseType GetProvisioningRequest(
      CdmProvisioningRequest* request,
      std::string* default_url);

  virtual CdmResponseType HandleProvisioningResponse(
      CdmProvisioningResponse& response);

  // Secure stop related methods
  virtual CdmResponseType GetSecureStops(CdmSecureStops* secure_stops);
  virtual CdmResponseType ReleaseSecureStops(
      const CdmSecureStopReleaseMessage& message);

  // Decryption and key related methods
  // Accept encrypted buffer and return decrypted data.
  virtual CdmResponseType Decrypt(const CdmSessionId& session_id,
                                  const CdmDecryptionParameters& parameters);

  // Is the key known to any session?
  virtual bool IsKeyValid(const KeyId& key_id);
  virtual bool FindSessionForKey(const KeyId& key_id, CdmSessionId* sessionId);

  // Event listener related methods
  virtual bool AttachEventListener(const CdmSessionId& session_id,
                                   WvCdmEventListener* listener);
  virtual bool DetachEventListener(const CdmSessionId& session_id,
                                   WvCdmEventListener* listener);

  // Parse a blob of multiple concatenated PSSH atoms to extract the first
  // widevine pssh
  static bool ExtractWidevinePssh(const CdmInitData& init_data,
                                  CdmInitData* output);

 private:
  // private methods
  // Cancel all sessions
  virtual bool CancelSessions();
  virtual bool ValidateKeySystem(const CdmKeySystem& key_system);

  // timer related methods to drive policy decisions
  virtual void EnablePolicyTimer();
  virtual void DisablePolicyTimer(bool force);
  virtual void OnTimerEvent();

  virtual void OnKeyReleaseEvent(const CdmKeySetId& key_set_id);

  // instance variables
  CdmSessionMap sessions_;
  CdmReleaseKeySetMap release_key_sets_;

  CertificateProvisioning cert_provisioning_;
  SecurityLevel cert_provisioning_requested_security_level_;

  // policy timer
  Timer policy_timer_;

  CORE_DISALLOW_COPY_AND_ASSIGN(CdmEngine);
};

}  // namespace wvcdm

#endif  // CDM_BASE_CDM_ENGINE_H_
