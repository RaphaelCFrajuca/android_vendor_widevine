// Copyright 2012 Google Inc. All Rights Reserved.

#ifndef CDM_BASE_LICENSE_H_
#define CDM_BASE_LICENSE_H_

#include <set>

#include "wv_cdm_types.h"

namespace video_widevine_server {
namespace sdk {
class SignedMessage;
}
}  // namespace video_widevine_server

namespace wvcdm {

class CryptoSession;
class PolicyEngine;

class CdmLicense {
 public:

  CdmLicense() : session_(NULL), initialized_(false) {}
  ~CdmLicense() {}

  bool Init(const std::string& token, CryptoSession* session,
            PolicyEngine* policy_engine);

  bool PrepareKeyRequest(const CdmInitData& pssh_data,
                         const CdmLicenseType license_type,
                         const CdmAppParameterMap& app_parameters,
                         const CdmSessionId& session_id,
                         CdmKeyMessage* signed_request,
                         std::string* server_url);
  bool PrepareKeyUpdateRequest(bool is_renewal, CdmKeyMessage* signed_request,
                               std::string* server_url);
  CdmResponseType HandleKeyResponse(const CdmKeyResponse& license_response);
  CdmResponseType HandleKeyUpdateResponse(
      bool is_renewal, const CdmKeyResponse& license_response);

  bool RestoreOfflineLicense(CdmKeyMessage& license_request,
                             CdmKeyResponse& license_response,
                             CdmKeyResponse& license_renewal_response);
  bool HasInitData() { return !init_data_.empty(); }
  bool IsKeyLoaded(const KeyId& key_id);

 private:
  bool PrepareServiceCertificateRequest(CdmKeyMessage* signed_request,
                                        std::string* server_url);
  CdmResponseType HandleServiceCertificateResponse(
      const video_widevine_server::sdk::SignedMessage& signed_message);

  CdmResponseType HandleKeyErrorResponse(
      const video_widevine_server::sdk::SignedMessage& signed_message);

  CryptoSession* session_;
  PolicyEngine* policy_engine_;
  std::string server_url_;
  std::string token_;
  std::string service_certificate_;
  std::string init_data_;
  bool initialized_;
  std::set<KeyId> loaded_keys_;

  // Used for certificate based licensing
  CdmKeyMessage key_request_;

  CORE_DISALLOW_COPY_AND_ASSIGN(CdmLicense);
};

}  // namespace wvcdm

#endif  // CDM_BASE_LICENSE_H_
