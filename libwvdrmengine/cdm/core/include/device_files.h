// Copyright 2013 Google Inc. All Rights Reserved.
//
#ifndef CDM_BASE_DEVICE_FILES_H_
#define CDM_BASE_DEVICE_FILES_H_

#include "wv_cdm_types.h"

namespace wvcdm {

class File;

class DeviceFiles {
 public:
  typedef enum {
    kLicenseStateActive,
    kLicenseStateReleasing,
    kLicenseStateUnknown,
  } LicenseState;

  DeviceFiles(): file_(NULL), security_level_(kSecurityLevelUninitialized),
                 initialized_(false) {}
  virtual ~DeviceFiles() {}

  virtual bool Init(const File* handle, CdmSecurityLevel security_level);

  virtual bool StoreCertificate(const std::string& certificate,
                                const std::string& wrapped_private_key);
  virtual bool RetrieveCertificate(std::string* certificate,
                                   std::string* wrapped_private_key);

  virtual bool StoreLicense(const std::string& key_set_id,
                            const LicenseState state,
                            const CdmInitData& pssh_data,
                            const CdmKeyMessage& key_request,
                            const CdmKeyResponse& key_response,
                            const CdmKeyMessage& key_renewal_request,
                            const CdmKeyResponse& key_renewal_response,
                            const std::string& release_server_url);
  virtual bool RetrieveLicense(const std::string& key_set_id,
                               LicenseState* state,
                               CdmInitData* pssh_data,
                               CdmKeyMessage* key_request,
                               CdmKeyResponse* key_response,
                               CdmKeyMessage* key_renewal_request,
                               CdmKeyResponse* key_renewal_response,
                               std::string* release_server_url);
  virtual bool DeleteLicense(const std::string& key_set_id);
  virtual bool DeleteAllFiles();
  virtual bool DeleteAllLicenses();
  virtual bool LicenseExists(const std::string& key_set_id);

  // For testing only
  static std::string GetCertificateFileName();
  static std::string GetLicenseFileNameExtension();

 protected:
  bool Hash(const std::string& data, std::string* hash);
  bool StoreFile(const char* name, const std::string& data);
  bool RetrieveFile(const char* name, std::string* data);

 private:
  virtual void SecurityLevelPathBackwardCompatibility();

  File* file_;
  CdmSecurityLevel security_level_;
  bool initialized_;

  CORE_DISALLOW_COPY_AND_ASSIGN(DeviceFiles);
};

}  // namespace wvcdm

#endif  // CDM_BASE_DEVICE_FILES_H_
