// Copyright 2013 Google Inc. All Rights Reserved.

#include "config_test_env.h"

namespace {
// Youtube Content Protection license server data
const std::string kYtCpLicenseServer =
    "http://kir03wwwg185.widevine.net/drm";
const std::string kYtCpClientAuth = "";
const std::string kYtCpKeyId =
    "000000347073736800000000"                   // blob size and pssh
    "EDEF8BA979D64ACEA3C827DCD51D21ED00000014"   // Widevine system id
    "0801121030313233343536373839616263646566";  // pssh data

// Youtube license server data
const std::string kYtLicenseServer =
    "https://www.youtube.com/api/drm/"
    "widevine?video_id=03681262dc412c06&source=YOUTUBE";
const std::string kYtClientAuth = "";
const std::string kYtKeyId =
    "000000347073736800000000"                   // blob size and pssh
    "EDEF8BA979D64ACEA3C827DCD51D21ED00000014"   // Widevine system id
    "0801121093789920E8D6520098577DF8F2DD5546";  // pssh data

// Google Play license server data
const std::string kGpLicenseServer =
    "https://jmt17.google.com/video-dev/license/GetCencLicense";

// NOTE: Append a userdata attribute to place a unique marker that the
// server team can use to track down specific requests during debugging
// e.g., "<existing-client-auth-string>&userdata=<your-ldap>.<your-tag>"
//       "<existing-client-auth-string>&userdata=jbmr2.dev"
const std::string kGpClientAuth =
    "?source=YOUTUBE&video_id=EGHC6OHNbOo&oauth=ya.gtsqawidevine";

const std::string kGpKeyId =
    "000000347073736800000000"                   // blob size and pssh
    "edef8ba979d64acea3c827dcd51d21ed00000014"   // Widevine system id
    "08011210e02562e04cd55351b14b3d748d36ed8e";  // pssh data

// An invalid key id, expected to fail
const std::string kWrongKeyId =
    "000000347073736800000000"                   // blob size and pssh
    "EDEF8BA979D64ACEA3C827DCD51D21ED00000014"   // Widevine system id
    "0901121094889920E8D6520098577DF8F2DD5546";  // pssh data

// Url returned by GetProvisioningRequest()
const std::string kProductionProvisioningServerUrl =
    "https://www.googleapis.com/"
    "certificateprovisioning/v1/devicecertificates/create"
    "?key=AIzaSyB-5OLKTx2iU5mko18DfdwK5611JIjbUhE";

// Return production-rooted certificates that have test bit set,
// request_license_test uses this url.
const std::string kProductionTestProvisioningServerUrl =
    "https://www.googleapis.com/"
    "certificateprovisioning/v1exttest/devicecertificates/create"
    "?key=AIzaSyB-5OLKTx2iU5mko18DfdwK5611JIjbUhE";

const std::string kServerSdkLicenseServer =
    "http://kir03fcpg174.widevine.net/widevine/cgi-bin/drm.cgi";

const wvcdm::ConfigTestEnv::LicenseServerConfiguration license_servers[] = {
  { wvcdm::kGooglePlayServer, kGpLicenseServer, kGpClientAuth, kGpKeyId,
    kDefaultHttpsPort, true, true },
  { wvcdm::kYouTubeContentProtectionServer, kYtCpLicenseServer,
    kYtCpClientAuth, kYtCpKeyId, kDefaultHttpPort, false, false }
};
}  // namespace

namespace wvcdm {

ConfigTestEnv::ConfigTestEnv(LicenseServerId server_id)
    : client_auth_(license_servers[server_id].client_tag),
      key_id_(license_servers[server_id].key_id),
      key_system_("com.widevine.alpha"),
      license_server_(license_servers[server_id].url),
      port_(license_servers[server_id].port),
      provisioning_server_url_(kProductionProvisioningServerUrl),
      provisioning_test_server_url_(kProductionTestProvisioningServerUrl),
      server_sdk_license_server_(kServerSdkLicenseServer),
      use_chunked_transfer_(license_servers[server_id].use_chunked_transfer),
      use_secure_transfer_(license_servers[server_id].use_secure_transfer),
      wrong_key_id_(kWrongKeyId) {}

}  // namespace wvcdm
