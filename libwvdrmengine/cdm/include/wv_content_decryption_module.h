// Copyright 2013 Google Inc. All Rights Reserved.

#ifndef CDM_BASE_WV_CONTENT_DECRYPTION_MODULE_H_
#define CDM_BASE_WV_CONTENT_DECRYPTION_MODULE_H_

#include "wv_cdm_types.h"

#include "utils/UniquePtr.h"

namespace wvcdm {

class CdmClientPropertySet;
class CdmEngine;
class WvCdmEventListener;

class WvContentDecryptionModule {
 public:
  WvContentDecryptionModule();
  virtual ~WvContentDecryptionModule();

  // Session related methods
  virtual CdmResponseType OpenSession(
      const CdmKeySystem& key_system,
      CdmClientPropertySet* property_set,
      CdmSessionId* session_id);
  virtual CdmResponseType CloseSession(const CdmSessionId& session_id);

  // Construct a valid license request.
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

  // Setup keys for offline usage which were retrived in an earlier key request
  virtual CdmResponseType RestoreKey(const CdmSessionId& session_id,
                                     const CdmKeySetId& key_set_id);

  // Cancel session
  virtual CdmResponseType CancelKeyRequest(const CdmSessionId& session_id);

  // Query system information
  virtual CdmResponseType QueryStatus(CdmQueryMap* key_info);

  // Query session information
  virtual CdmResponseType QuerySessionStatus(const CdmSessionId& session_id,
                                             CdmQueryMap* key_info);

  // Query license information
  virtual CdmResponseType QueryKeyStatus(const CdmSessionId& session_id,
                                         CdmQueryMap* key_info);

  // Query session control information
  virtual CdmResponseType QueryKeyControlInfo(const CdmSessionId& session_id,
                                              CdmQueryMap* key_info);

  // Provisioning related methods
  virtual CdmResponseType GetProvisioningRequest(
      CdmProvisioningRequest* request, std::string* default_url);

  virtual CdmResponseType HandleProvisioningResponse(
      CdmProvisioningResponse& response);

  // Secure stop related methods
  virtual CdmResponseType GetSecureStops(CdmSecureStops* secure_stops);
  virtual CdmResponseType ReleaseSecureStops(
      const CdmSecureStopReleaseMessage& message);

  // Accept encrypted buffer and decrypt data.
  // Decryption parameters that need to be specified are
  // is_encrypted, is_secure, key_id, encrypt_buffer, encrypt_length,
  // iv, block_offset, decrypt_buffer, decrypt_buffer_length,
  // decrypt_buffer_offset and subsample_flags
  virtual CdmResponseType Decrypt(const CdmSessionId& session_id,
                                  const CdmDecryptionParameters& parameters);

  // Event listener related methods
  virtual bool AttachEventListener(const CdmSessionId& session_id,
                                   WvCdmEventListener* listener);
  virtual bool DetachEventListener(const CdmSessionId& session_id,
                                   WvCdmEventListener* listener);

 private:
  uint32_t GenerateSessionSharingId();

  // instance variables
  UniquePtr<CdmEngine> cdm_engine_;

  CORE_DISALLOW_COPY_AND_ASSIGN(WvContentDecryptionModule);
};

}  // namespace wvcdm

#endif  // CDM_BASE_WV_CONTENT_DECRYPTION_MODULE_H_
