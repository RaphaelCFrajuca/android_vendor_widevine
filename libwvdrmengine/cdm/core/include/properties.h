// Copyright 2013 Google Inc. All Rights Reserved.

#ifndef CDM_BASE_PROPERTIES_H_
#define CDM_BASE_PROPERTIES_H_

#include <map>
#include <string>

#include "cdm_client_property_set.h"
#include "lock.h"
#include "scoped_ptr.h"
#include "wv_cdm_types.h"

namespace wvcdm {

typedef std::map<CdmSessionId, const CdmClientPropertySet*>
  CdmClientPropertySetMap;

// This class saves information about features and properties enabled
// for a given platform. At initialization it initializes properties from
// property_configuration.h. That file specifies features selected for each
// platform. Core CDM can then query enabled features though specific getter
// methods.
// Setter methods are provided but their only planned use is for testing.
class Properties {
 public:
  static void Init();

  static inline bool begin_license_usage_when_received() {
    return begin_license_usage_when_received_;
  }
  static inline bool require_explicit_renew_request() {
    return require_explicit_renew_request_;
  }
  static inline bool oem_crypto_use_secure_buffers() {
    return oem_crypto_use_secure_buffers_;
  }
  static inline bool oem_crypto_use_fifo() { return oem_crypto_use_fifo_; }
  static inline bool oem_crypto_use_userspace_buffers() {
    return oem_crypto_use_userspace_buffers_;
  }
  static inline bool use_certificates_as_identification() {
    return use_certificates_as_identification_;
  }
  static inline bool extract_pssh_data() {
    return extract_pssh_data_;
  }
  static inline bool decrypt_with_empty_session_support() {
    return decrypt_with_empty_session_support_;
  }
  static inline bool security_level_path_backward_compatibility_support() {
    return security_level_path_backward_compatibility_support_;
  }
  static bool GetCompanyName(std::string* company_name);
  static bool GetModelName(std::string* model_name);
  static bool GetArchitectureName(std::string* arch_name);
  static bool GetDeviceName(std::string* device_name);
  static bool GetProductName(std::string* product_name);
  static bool GetBuildInfo(std::string* build_info);
  static bool GetDeviceFilesBasePath(CdmSecurityLevel security_level,
                                     std::string* base_path);
  static bool GetFactoryKeyboxPath(std::string* keybox);
  static bool GetOEMCryptoPath(std::string* library_name);
  static bool GetSecurityLevelDirectories(std::vector<std::string>* dirs);
  static const std::string GetSecurityLevel(const CdmSessionId& session_id);
  static const std::vector<uint8_t> GetServiceCertificate(
       const CdmSessionId& session_id);
  static bool UsePrivacyMode(const CdmSessionId& session_id);
  static uint32_t GetSessionSharingId(const CdmSessionId& session_id);

  static bool AddSessionPropertySet(
      const CdmSessionId& session_id,
      const CdmClientPropertySet* property_set);
  static bool RemoveSessionPropertySet(const CdmSessionId& session_id);

 private:
  static const CdmClientPropertySet* GetCdmClientPropertySet(
      const CdmSessionId& session_id);
  static void set_begin_license_usage_when_received(bool flag) {
    begin_license_usage_when_received_ = flag;
  }
  static void set_require_explicit_renew_request(bool flag) {
    require_explicit_renew_request_ = flag;
  }
  static void set_oem_crypto_use_secure_buffers(bool flag) {
    oem_crypto_use_secure_buffers_ = flag;
  }
  static void set_oem_crypto_use_fifo(bool flag) {
    oem_crypto_use_fifo_ = flag;
  }
  static void set_oem_crypto_use_userspace_buffers(bool flag) {
    oem_crypto_use_userspace_buffers_ = flag;
  }
  static void set_use_certificates_as_identification(bool flag) {
    use_certificates_as_identification_ = flag;
  }
  static void set_extract_pssh_data(bool flag) {
    extract_pssh_data_ = flag;
  }
  static void set_decrypt_with_empty_session_support(bool flag) {
    decrypt_with_empty_session_support_ = flag;
  }
  static void set_security_level_path_backward_compatibility_support(bool flag) {
    security_level_path_backward_compatibility_support_ = flag;
  }

  static bool begin_license_usage_when_received_;
  static bool require_explicit_renew_request_;
  static bool oem_crypto_use_secure_buffers_;
  static bool oem_crypto_use_fifo_;
  static bool oem_crypto_use_userspace_buffers_;
  static bool use_certificates_as_identification_;
  static bool extract_pssh_data_;
  static bool decrypt_with_empty_session_support_;
  static bool security_level_path_backward_compatibility_support_;
  static scoped_ptr<CdmClientPropertySetMap> session_property_set_;

  CORE_DISALLOW_COPY_AND_ASSIGN(Properties);
};

}  // namespace wvcdm

#endif  // CDM_BASE_PROPERTIES_H_
