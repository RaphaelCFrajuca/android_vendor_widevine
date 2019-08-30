// Copyright 2012 Google Inc. All Rights Reserved.

#ifndef CDM_BASE_WV_CDM_CONSTANTS_H_
#define CDM_BASE_WV_CDM_CONSTANTS_H_

#include <string>

namespace wvcdm {
static const size_t KEY_CONTROL_SIZE = 16;
// TODO(kqyang): Key ID size is not fixed in spec, but conventionally we
// always use 16 bytes key id. We'll need to update oemcrypto to support
// variable size key id.
static const size_t KEY_ID_SIZE = 16;
static const size_t KEY_IV_SIZE = 16;
static const size_t KEY_PAD_SIZE = 16;
static const size_t KEY_SIZE = 16;
static const size_t MAC_KEY_SIZE = 32;
static const size_t KEYBOX_KEY_DATA_SIZE = 72;

static const char SESSION_ID_PREFIX[] = "sid";
static const char KEY_SET_ID_PREFIX[] = "ksid";
static const char KEY_SYSTEM[] = "com.widevine";

// define query keys, values here
static const std::string QUERY_KEY_LICENSE_TYPE = "LicenseType";
                                                    // "Streaming", "Offline"
static const std::string QUERY_KEY_PLAY_ALLOWED = "PlayAllowed";
                                                    // "True", "False"
static const std::string QUERY_KEY_PERSIST_ALLOWED = "PersistAllowed";
                                                    // "True", "False"
static const std::string QUERY_KEY_RENEW_ALLOWED = "RenewAllowed";
                                                    // "True", "False"
static const std::string QUERY_KEY_LICENSE_DURATION_REMAINING =
    "LicenseDurationRemaining";                     // non-negative integer
static const std::string QUERY_KEY_PLAYBACK_DURATION_REMAINING =
    "PlaybackDurationRemaining";                    // non-negative integer
static const std::string QUERY_KEY_RENEWAL_SERVER_URL = "RenewalServerUrl";
                                                    // url
static const std::string QUERY_KEY_OEMCRYPTO_SESSION_ID = "OemCryptoSessionId";
                                                    // session id
static const std::string QUERY_KEY_SECURITY_LEVEL = "SecurityLevel";
                                                    // "L1", "L3"
static const std::string QUERY_KEY_DEVICE_ID = "DeviceID";
                                               // device unique id
static const std::string QUERY_KEY_SYSTEM_ID = "SystemID";
                                               // system id
static const std::string QUERY_KEY_PROVISIONING_ID = "ProvisioningID";
                                               // provisioning unique id

static const std::string QUERY_VALUE_TRUE = "True";
static const std::string QUERY_VALUE_FALSE = "False";
static const std::string QUERY_VALUE_STREAMING = "Streaming";
static const std::string QUERY_VALUE_OFFLINE = "Offline";
static const std::string QUERY_VALUE_SECURITY_LEVEL_L1 = "L1";
static const std::string QUERY_VALUE_SECURITY_LEVEL_L2 = "L2";
static const std::string QUERY_VALUE_SECURITY_LEVEL_L3 = "L3";
static const std::string QUERY_VALUE_SECURITY_LEVEL_Unknown = "Unknown";

}  // namespace wvcdm

#endif  // CDM_BASE_WV_CDM_CONSTANTS_H_
