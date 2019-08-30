// Copyright 2013 Google Inc. All Rights Reserved.

#include "device_files.h"

#include <cstring>
#include <string>

#include "device_files.pb.h"
#include "file_store.h"
#include "log.h"
#include "openssl/sha.h"
#include "properties.h"

// Protobuf generated classes.
using video_widevine_client::sdk::DeviceCertificate;
using video_widevine_client::sdk::HashedFile;
using video_widevine_client::sdk::License;
using video_widevine_client::sdk::License_LicenseState_ACTIVE;
using video_widevine_client::sdk::License_LicenseState_RELEASING;

namespace {
const char kCertificateFileName[] = "cert.bin";
const char kLicenseFileNameExt[] = ".lic";
const char kWildcard[] = "*";
const char kPathDelimiter[] = "/";
const char *kSecurityLevelPathCompatibilityExclusionList[] = { "ay64.dat" };
}  // namespace

namespace wvcdm {

bool DeviceFiles::Init(const File* handle, CdmSecurityLevel security_level) {
  if (handle == NULL) {
    LOGW("DeviceFiles::Init: Invalid file handle parameter");
    return false;
  }
  switch (security_level) {
    case kSecurityLevelL1:
    case kSecurityLevelL2:
    case kSecurityLevelL3:
      break;
    default:
      LOGW("DeviceFiles::Init: Unsupported security level %d", security_level);
      return false;
  }
  file_ = const_cast<File*>(handle);
  security_level_ = security_level;
  initialized_ = true;
  return true;
}

bool DeviceFiles::StoreCertificate(const std::string& certificate,
                                   const std::string& wrapped_private_key) {
  if (!initialized_) {
    LOGW("DeviceFiles::StoreCertificate: not initialized");
    return false;
  }

  // Fill in file information
  video_widevine_client::sdk::File file;

  file.set_type(video_widevine_client::sdk::File::DEVICE_CERTIFICATE);
  file.set_version(video_widevine_client::sdk::File::VERSION_1);

  DeviceCertificate* device_certificate = file.mutable_device_certificate();
  device_certificate->set_certificate(certificate);
  device_certificate->set_wrapped_private_key(wrapped_private_key);

  std::string serialized_string;
  file.SerializeToString(&serialized_string);

  // calculate SHA hash
  std::string hash;
  if (!Hash(serialized_string, &hash)) {
    LOGW("DeviceFiles::StoreCertificate: Hash computation failed");
    return false;
  }

  // Fill in hashed file data
  HashedFile hashed_file;
  hashed_file.set_file(serialized_string);
  hashed_file.set_hash(hash);

  hashed_file.SerializeToString(&serialized_string);

  return StoreFile(kCertificateFileName, serialized_string);
}

bool DeviceFiles::RetrieveCertificate(std::string* certificate,
                                      std::string* wrapped_private_key) {
  if (!initialized_) {
    LOGW("DeviceFiles::RetrieveCertificate: not initialized");
    return false;
  }

  if (Properties::security_level_path_backward_compatibility_support()) {
    SecurityLevelPathBackwardCompatibility();
  }

  std::string serialized_hashed_file;
  if (!RetrieveFile(kCertificateFileName, &serialized_hashed_file))
    return false;

  HashedFile hashed_file;
  if (!hashed_file.ParseFromString(serialized_hashed_file)) {
    LOGW("DeviceFiles::RetrieveCertificate: Unable to parse hash file");
    return false;
  }

  std::string hash;
  if (!Hash(hashed_file.file(), &hash)) {
    LOGW("DeviceFiles::RetrieveCertificate: Hash computation failed");
    return false;
  }

  if (hash.compare(hashed_file.hash())) {
    LOGW("DeviceFiles::RetrieveCertificate: Hash mismatch");
    return false;
  }

  video_widevine_client::sdk::File file;
  if (!file.ParseFromString(hashed_file.file())) {
    LOGW("DeviceFiles::RetrieveCertificate: Unable to parse file");
    return false;
  }

  if (file.type() != video_widevine_client::sdk::File::DEVICE_CERTIFICATE) {
    LOGW("DeviceFiles::RetrieveCertificate: Incorrect file type");
    return false;
  }

  if (file.version() != video_widevine_client::sdk::File::VERSION_1) {
    LOGW("DeviceFiles::RetrieveCertificate: Incorrect file version");
    return false;
  }

  if (!file.has_device_certificate()) {
    LOGW("DeviceFiles::RetrieveCertificate: Certificate not present");
    return false;
  }

  DeviceCertificate device_certificate = file.device_certificate();

  *certificate = device_certificate.certificate();
  *wrapped_private_key = device_certificate.wrapped_private_key();
  return true;
}

bool DeviceFiles::StoreLicense(const std::string& key_set_id,
                               const LicenseState state,
                               const CdmInitData& pssh_data,
                               const CdmKeyMessage& license_request,
                               const CdmKeyResponse& license_message,
                               const CdmKeyMessage& license_renewal_request,
                               const CdmKeyResponse& license_renewal,
                               const std::string& release_server_url) {
  if (!initialized_) {
    LOGW("DeviceFiles::StoreLicense: not initialized");
    return false;
  }

  // Fill in file information
  video_widevine_client::sdk::File file;

  file.set_type(video_widevine_client::sdk::File::LICENSE);
  file.set_version(video_widevine_client::sdk::File::VERSION_1);

  License* license = file.mutable_license();
  switch (state) {
    case kLicenseStateActive:
      license->set_state(License_LicenseState_ACTIVE);
      break;
    case kLicenseStateReleasing:
      license->set_state(License_LicenseState_RELEASING);
      break;
    default:
      LOGW("DeviceFiles::StoreLicense: Unknown license state: %u", state);
      return false;
      break;
  }
  license->set_pssh_data(pssh_data);
  license->set_license_request(license_request);
  license->set_license(license_message);
  license->set_renewal_request(license_renewal_request);
  license->set_renewal(license_renewal);
  license->set_release_server_url(release_server_url);

  std::string serialized_string;
  file.SerializeToString(&serialized_string);

  // calculate SHA hash
  std::string hash;
  if (!Hash(serialized_string, &hash)) {
    LOGW("DeviceFiles::StoreLicense: Hash computation failed");
    return false;
  }

  // File in hashed file data
  HashedFile hashed_file;
  hashed_file.set_file(serialized_string);
  hashed_file.set_hash(hash);

  hashed_file.SerializeToString(&serialized_string);

  std::string file_name = key_set_id + kLicenseFileNameExt;
  return StoreFile(file_name.c_str(), serialized_string);
}

bool DeviceFiles::RetrieveLicense(const std::string& key_set_id,
                                  LicenseState* state, CdmInitData* pssh_data,
                                  CdmKeyMessage* license_request,
                                  CdmKeyResponse* license_message,
                                  CdmKeyMessage* license_renewal_request,
                                  CdmKeyResponse* license_renewal,
                                  std::string* release_server_url) {
  if (!initialized_) {
    LOGW("DeviceFiles::RetrieveLicense: not initialized");
    return false;
  }

  std::string serialized_hashed_file;
  std::string file_name = key_set_id + kLicenseFileNameExt;
  if (!RetrieveFile(file_name.c_str(), &serialized_hashed_file)) return false;

  HashedFile hashed_file;
  if (!hashed_file.ParseFromString(serialized_hashed_file)) {
    LOGW("DeviceFiles::RetrieveLicense: Unable to parse hash file");
    return false;
  }

  std::string hash;
  if (!Hash(hashed_file.file(), &hash)) {
    LOGW("DeviceFiles::RetrieveLicense: Hash computation failed");
    return false;
  }

  if (hash.compare(hashed_file.hash())) {
    LOGW("DeviceFiles::RetrieveLicense: Hash mismatch");
    return false;
  }

  video_widevine_client::sdk::File file;
  if (!file.ParseFromString(hashed_file.file())) {
    LOGW("DeviceFiles::RetrieveLicense: Unable to parse file");
    return false;
  }

  if (file.type() != video_widevine_client::sdk::File::LICENSE) {
    LOGW("DeviceFiles::RetrieveLicense: Incorrect file type");
    return false;
  }

  if (file.version() != video_widevine_client::sdk::File::VERSION_1) {
    LOGW("DeviceFiles::RetrieveLicense: Incorrect file version");
    return false;
  }

  if (!file.has_license()) {
    LOGW("DeviceFiles::RetrieveLicense: License not present");
    return false;
  }

  License license = file.license();

  switch (license.state()) {
    case License_LicenseState_ACTIVE:
      *state = kLicenseStateActive;
      break;
    case License_LicenseState_RELEASING:
      *state = kLicenseStateReleasing;
      break;
    default:
      LOGW("DeviceFiles::RetrieveLicense: Unrecognized license state: %u",
           kLicenseStateUnknown);
      *state = kLicenseStateUnknown;
      break;
  }
  *pssh_data = license.pssh_data();
  *license_request = license.license_request();
  *license_message = license.license();
  *license_renewal_request = license.renewal_request();
  *license_renewal = license.renewal();
  *release_server_url = license.release_server_url();
  return true;
}

bool DeviceFiles::DeleteLicense(const std::string& key_set_id) {
  if (!initialized_) {
    LOGW("DeviceFiles::DeleteLicense: not initialized");
    return false;
  }

  std::string path;
  if (!Properties::GetDeviceFilesBasePath(security_level_, &path)) {
    LOGW("DeviceFiles::DeleteLicense: Unable to get base path");
    return false;
  }
  path.append(key_set_id);
  path.append(kLicenseFileNameExt);

  return file_->Remove(path);
}

bool DeviceFiles::DeleteAllLicenses() {
  if (!initialized_) {
    LOGW("DeviceFiles::DeleteAllLicenses: not initialized");
    return false;
  }

  std::string path;
  if (!Properties::GetDeviceFilesBasePath(security_level_, &path)) {
    LOGW("DeviceFiles::DeleteAllLicenses: Unable to get base path");
    return false;
  }
  path.append(kWildcard);
  path.append(kLicenseFileNameExt);

  return file_->Remove(path);
}

bool DeviceFiles::DeleteAllFiles() {
  if (!initialized_) {
    LOGW("DeviceFiles::DeleteAllFiles: not initialized");
    return false;
  }

  std::string path;
  if (!Properties::GetDeviceFilesBasePath(security_level_, &path)) {
    LOGW("DeviceFiles::DeleteAllFiles: Unable to get base path");
    return false;
  }

  return file_->Remove(path);
}

bool DeviceFiles::LicenseExists(const std::string& key_set_id) {
  if (!initialized_) {
    LOGW("DeviceFiles::LicenseExists: not initialized");
    return false;
  }

  std::string path;
  if (!Properties::GetDeviceFilesBasePath(security_level_, &path)) {
    LOGW("DeviceFiles::StoreFile: Unable to get base path");
    return false;
  }
  path.append(key_set_id);
  path.append(kLicenseFileNameExt);

  return file_->Exists(path);
}

bool DeviceFiles::Hash(const std::string& data, std::string* hash) {
  if (!hash) return false;

  hash->resize(SHA256_DIGEST_LENGTH);
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, data.data(), data.size());
  SHA256_Final(reinterpret_cast<unsigned char*>(&(*hash)[0]), &sha256);
  return true;
}

bool DeviceFiles::StoreFile(const char* name, const std::string& data) {
  if (!file_) {
    LOGW("DeviceFiles::StoreFile: Invalid file handle");
    return false;
  }

  if (!name) {
    LOGW("DeviceFiles::StoreFile: Unspecified file name parameter");
    return false;
  }

  std::string path;
  if (!Properties::GetDeviceFilesBasePath(security_level_, &path)) {
    LOGW("DeviceFiles::StoreFile: Unable to get base path");
    return false;
  }

  if (!file_->IsDirectory(path)) {
    if (!file_->CreateDirectory(path)) return false;
  }

  path += name;

  if (!file_->Open(path, File::kCreate | File::kTruncate | File::kBinary)) {
    LOGW("DeviceFiles::StoreFile: File open failed: %s", path.c_str());
    return false;
  }

  ssize_t bytes = file_->Write(data.data(), data.size());
  file_->Close();

  if (bytes != static_cast<ssize_t>(data.size())) {
    LOGW("DeviceFiles::StoreFile: write failed: %d %d", data.size(), bytes);
    return false;
  }

  LOGV("DeviceFiles::StoreFile: success: %s (%db)", path.c_str(), data.size());
  return true;
}

bool DeviceFiles::RetrieveFile(const char* name, std::string* data) {
  if (!file_) {
    LOGW("DeviceFiles::RetrieveFile: Invalid file handle");
    return false;
  }

  if (!name) {
    LOGW("DeviceFiles::RetrieveFile: Unspecified file name parameter");
    return false;
  }

  if (!data) {
    LOGW("DeviceFiles::RetrieveFile: Unspecified data parameter");
    return false;
  }

  std::string path;
  if (!Properties::GetDeviceFilesBasePath(security_level_, &path)) {
    LOGW("DeviceFiles::StoreFile: Unable to get base path");
    return false;
  }

  path += name;

  if (!file_->Exists(path)) {
    LOGW("DeviceFiles::RetrieveFile: %s does not exist", path.c_str());
    return false;
  }

  ssize_t bytes = file_->FileSize(path);
  if (bytes <= 0) {
    LOGW("DeviceFiles::RetrieveFile: File size invalid: %d", path.c_str());
    return false;
  }

  if (!file_->Open(path, File::kReadOnly | File::kBinary)) {
    LOGW("DeviceFiles::RetrieveFile: File open failed: %s", path.c_str());
    return false;
  }

  data->resize(bytes);
  bytes = file_->Read(&(*data)[0], data->size());
  file_->Close();

  if (bytes != static_cast<ssize_t>(data->size())) {
    LOGW("DeviceFiles::RetrieveFile: read failed");
    return false;
  }

  LOGV("DeviceFiles::RetrieveFile: success: %s (%db)", path.c_str(),
       data->size());
  return true;
}

void DeviceFiles::SecurityLevelPathBackwardCompatibility() {
  std::string path;
  if (!Properties::GetDeviceFilesBasePath(security_level_, &path)) {
    LOGW("DeviceFiles::SecurityLevelPathBackwardCompatibility: Unable to "
        "get base path");
    return;
  }

  std::vector<std::string> security_dirs;
  if (!Properties::GetSecurityLevelDirectories(&security_dirs)) {
    LOGW("DeviceFiles::SecurityLevelPathBackwardCompatibility: Unable to "
        "get security directories");
    return;
  }

  size_t pos = std::string::npos;
  for (size_t i = 0; i < security_dirs.size(); ++i) {
    pos = path.rfind(security_dirs[i]);
    if (std::string::npos != pos)
      break;
  }

  if (pos == std::string::npos) {
    LOGV("DeviceFiles::SecurityLevelPathBackwardCompatibility: Security level "
        "specific path not found. Check properties?");
    return;
  }

  std::string from_dir(path, 0, pos);

  std::vector<std::string> files;
  file_->List(from_dir, &files);

  for (size_t i = 0; i < files.size(); ++i) {
    std::string from = from_dir + files[i];
    bool exclude = false;
    for (size_t j = 0;
         j < sizeof(kSecurityLevelPathCompatibilityExclusionList) /
             sizeof(const char*);
         j++) {
      if (files[i].compare(kSecurityLevelPathCompatibilityExclusionList[j]) == 0) {
        exclude = true;
        break;
      }
    }
    if (exclude) continue;
    if (!file_->IsRegularFile(from)) continue;

    for (size_t j = 0; j < security_dirs.size(); ++j) {
      std::string to_dir = from_dir + security_dirs[j];
      if (!file_->Exists(to_dir))
        file_->CreateDirectory(to_dir);
      std::string to = to_dir + files[i];
      file_->Copy(from, to);
    }
    file_->Remove(from);
  }
}

std::string DeviceFiles::GetCertificateFileName() {
  return kCertificateFileName;
}

std::string DeviceFiles::GetLicenseFileNameExtension() {
  return kLicenseFileNameExt;
}

}  // namespace wvcdm
