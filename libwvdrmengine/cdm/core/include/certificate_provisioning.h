// Copyright 2013 Google Inc. All Rights Reserved.

#ifndef CDM_BASE_CERTIFICATE_PROVISIONING_H_
#define CDM_BASE_CERTIFICATE_PROVISIONING_H_

#include "crypto_session.h"
#include "oemcrypto_adapter.h"
#include "wv_cdm_types.h"

namespace wvcdm {

class CdmSession;

class CertificateProvisioning {
 public:
  CertificateProvisioning() {};
  ~CertificateProvisioning() {};

  // Provisioning related methods
  CdmResponseType GetProvisioningRequest(SecurityLevel requested_security_level,
                                         CdmProvisioningRequest* request,
                                         std::string* default_url);
  CdmResponseType HandleProvisioningResponse(CdmProvisioningResponse& response);

 private:
  void ComposeJsonRequestAsQueryString(const std::string& message,
                                       CdmProvisioningRequest* request);
  bool ParseJsonResponse(const CdmProvisioningResponse& json_str,
                         const std::string& start_substr,
                         const std::string& end_substr,
                         std::string* result);
  CryptoSession crypto_session_;

  CORE_DISALLOW_COPY_AND_ASSIGN(CertificateProvisioning);
};
}  // namespace wvcdm

#endif  // CDM_BASE_CERTIFICATE_PROVISIONING_H_
