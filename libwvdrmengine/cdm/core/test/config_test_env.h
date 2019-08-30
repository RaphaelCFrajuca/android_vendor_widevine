// Copyright 2013 Google Inc. All Rights Reserved.

#ifndef CDM_TEST_CONFIG_TEST_ENV_H_
#define CDM_TEST_CONFIG_TEST_ENV_H_

#include <string>
#include "wv_cdm_types.h"

namespace {
const std::string kDefaultHttpsPort = "443";
const std::string kDefaultHttpPort = "80";
}

namespace wvcdm {
typedef enum {
  kGooglePlayServer,
  kYouTubeContentProtectionServer
} LicenseServerId;

// Configures default test environment.
class ConfigTestEnv {
 public:
  typedef struct {
    LicenseServerId id;
    std::string url;
    std::string client_tag;
    std::string key_id;
    std::string port;
    bool use_chunked_transfer;
    bool use_secure_transfer;
  } LicenseServerConfiguration;

  explicit ConfigTestEnv(LicenseServerId server_id);
  ~ConfigTestEnv() {};

  const std::string& client_auth() const { return client_auth_; }
  const KeyId& key_id() const { return key_id_; }
  const CdmKeySystem& key_system() const { return key_system_; }
  const std::string& license_server() const { return license_server_; }
  const std::string& port() const { return port_; }
  const std::string& provisioning_server_url() const {
    return provisioning_server_url_;
  }
  const std::string& provisioning_test_server_url() const {
    return provisioning_test_server_url_;
  }
  const std::string& server_sdk_license_server() const {
    return server_sdk_license_server_;
  }
  bool use_chunked_transfer() { return use_chunked_transfer_; }
  bool use_secure_transfer() { return use_secure_transfer_; }
  const KeyId& wrong_key_id() const { return wrong_key_id_; }

  void set_key_id(KeyId& key_id) { key_id_.assign(key_id); }
  void set_key_system(CdmKeySystem& key_system) {
    key_system_.assign(key_system);
  }
  void set_license_server(std::string& license_server) {
    license_server_.assign(license_server);
  }
  void set_port(std::string& port) { port_.assign(port); }

 private:
  std::string client_auth_;
  KeyId key_id_;
  CdmKeySystem key_system_;
  std::string license_server_;
  std::string port_;
  std::string provisioning_server_url_;
  std::string provisioning_test_server_url_;
  std::string server_sdk_license_server_;
  bool use_chunked_transfer_;
  bool use_secure_transfer_;
  KeyId wrong_key_id_;

  CORE_DISALLOW_COPY_AND_ASSIGN(ConfigTestEnv);
};

};  // namespace wvcdm

#endif  // CDM_TEST_CONFIG_TEST_ENV_H_
