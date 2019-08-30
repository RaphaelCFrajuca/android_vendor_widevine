// Copyright 2013 Google Inc. All Rights Reserved.

#include <errno.h>
#include <getopt.h>
#include <sstream>

#include "config_test_env.h"
#include "gtest/gtest.h"
#include "device_files.h"
#include "file_store.h"
#include "license_request.h"
#include "log.h"
#include "OEMCryptoCENC.h"
#include "oemcrypto_adapter.h"
#include "properties.h"
#include "string_conversions.h"
#include "url_request.h"
#include "wv_cdm_constants.h"
#include "wv_cdm_event_listener.h"
#include "wv_content_decryption_module.h"

namespace {
// Default license server, can be configured using --server command line option
// Default key id (pssh), can be configured using --keyid command line option
std::string g_client_auth;
wvcdm::ConfigTestEnv* g_config = NULL;
wvcdm::KeyId g_key_id;
wvcdm::CdmKeySystem g_key_system;
std::string g_license_server;
std::string g_port;
wvcdm::KeyId g_wrong_key_id;
bool g_use_chunked_transfer = false;
bool g_use_full_path = false;
bool g_use_secure_transfer = false;
wvcdm::LicenseServerId g_license_server_id = wvcdm::kGooglePlayServer;

std::string kServiceCertificate =
    "0803121028703454C008F63618ADE7443DB6C4C8188BE7F99005228E023082010"
    "A0282010100B52112B8D05D023FCC5D95E2C251C1C649B4177CD8D2BEEF355BB0"
    "6743DE661E3D2ABC3182B79946D55FDC08DFE95407815E9A6274B322A2C7F5E06"
    "7BB5F0AC07A89D45AEA94B2516F075B66EF811D0D26E1B9A6B894F2B9857962AA"
    "171C4F66630D3E4C602718897F5E1EF9B6AAF5AD4DBA2A7E14176DF134A1D3185"
    "B5A218AC05A4C41F081EFFF80A3A040C50B09BBC740EEDCD8F14D675A91980F92"
    "CA7DDC646A06ADAD5101F74A0E498CC01F00532BAC217850BD905E90923656B7D"
    "FEFEF42486767F33EF6283D4F4254AB72589390BEE55808F1D668080D45D893C2"
    "BCA2F74D60A0C0D0A0993CEF01604703334C3638139486BC9DAF24FD67A07F9AD"
    "94302030100013A1273746167696E672E676F6F676C652E636F6D";

// TODO(rfrias): refactor to print out the decryption test names
struct SubSampleInfo {
  bool retrieve_key;
  size_t num_of_subsamples;
  bool is_encrypted;
  bool is_secure;
  wvcdm::KeyId key_id;
  std::vector<uint8_t> encrypt_data;
  std::vector<uint8_t> decrypt_data;
  std::vector<uint8_t> iv;
  size_t block_offset;
};

SubSampleInfo clear_sub_sample = {
    true, 1, false, false, wvcdm::a2bs_hex("E02562E04CD55351B14B3D748D36ED8E"),
    wvcdm::a2b_hex(
        "9da401105ab8da443e93e6fe089dfc69e00a9a51690d406872f338c5fa7dd3d5"
        "abf8dfd660aaff3e327850a56eedf707c03e2d1a00f9f0371e3e19ea32b13267"
        "7bc083ccbb83e6d9c03794ee97f50081221a8e5eb123f6dfa895e7a971166483"
        "cdadd61cd8d0f859501e750e9d356d57252ecd9f7388459f5470de9d92198c44"
        "0b520055b3b9a1c6b2c9d21e78dce99622d9d031fc7dee28a6d1d6dfb81502eb"
        "463c4c189555f496d9aa529b3f5522e9f46dcf70b2bfe8df47daf02b6a267f93"
        "f80d871786eb4bd7f08f9c52079c034a9534d885ba4c00cbe2234cfbb5205a56"
        "41dd760f83d0f09f27881ad490efa8b99b7ab24b34311a2e8416b1a80d736ad7"),
    wvcdm::a2b_hex(
        "9da401105ab8da443e93e6fe089dfc69e00a9a51690d406872f338c5fa7dd3d5"
        "abf8dfd660aaff3e327850a56eedf707c03e2d1a00f9f0371e3e19ea32b13267"
        "7bc083ccbb83e6d9c03794ee97f50081221a8e5eb123f6dfa895e7a971166483"
        "cdadd61cd8d0f859501e750e9d356d57252ecd9f7388459f5470de9d92198c44"
        "0b520055b3b9a1c6b2c9d21e78dce99622d9d031fc7dee28a6d1d6dfb81502eb"
        "463c4c189555f496d9aa529b3f5522e9f46dcf70b2bfe8df47daf02b6a267f93"
        "f80d871786eb4bd7f08f9c52079c034a9534d885ba4c00cbe2234cfbb5205a56"
        "41dd760f83d0f09f27881ad490efa8b99b7ab24b34311a2e8416b1a80d736ad7"),
    wvcdm::a2b_hex("50a6c61c3f7c2b37e72b0c047000dd4a"), 0};

SubSampleInfo clear_sub_sample_no_key = {
    false, 1, false, false, wvcdm::a2bs_hex("77777777777777777777777777777777"),
    wvcdm::a2b_hex(
        "9da401105ab8da443e93e6fe089dfc69e00a9a51690d406872f338c5fa7dd3d5"
        "abf8dfd660aaff3e327850a56eedf707c03e2d1a00f9f0371e3e19ea32b13267"
        "7bc083ccbb83e6d9c03794ee97f50081221a8e5eb123f6dfa895e7a971166483"
        "cdadd61cd8d0f859501e750e9d356d57252ecd9f7388459f5470de9d92198c44"
        "0b520055b3b9a1c6b2c9d21e78dce99622d9d031fc7dee28a6d1d6dfb81502eb"
        "463c4c189555f496d9aa529b3f5522e9f46dcf70b2bfe8df47daf02b6a267f93"
        "f80d871786eb4bd7f08f9c52079c034a9534d885ba4c00cbe2234cfbb5205a56"
        "41dd760f83d0f09f27881ad490efa8b99b7ab24b34311a2e8416b1a80d736ad7"),
    wvcdm::a2b_hex(
        "9da401105ab8da443e93e6fe089dfc69e00a9a51690d406872f338c5fa7dd3d5"
        "abf8dfd660aaff3e327850a56eedf707c03e2d1a00f9f0371e3e19ea32b13267"
        "7bc083ccbb83e6d9c03794ee97f50081221a8e5eb123f6dfa895e7a971166483"
        "cdadd61cd8d0f859501e750e9d356d57252ecd9f7388459f5470de9d92198c44"
        "0b520055b3b9a1c6b2c9d21e78dce99622d9d031fc7dee28a6d1d6dfb81502eb"
        "463c4c189555f496d9aa529b3f5522e9f46dcf70b2bfe8df47daf02b6a267f93"
        "f80d871786eb4bd7f08f9c52079c034a9534d885ba4c00cbe2234cfbb5205a56"
        "41dd760f83d0f09f27881ad490efa8b99b7ab24b34311a2e8416b1a80d736ad7"),
    wvcdm::a2b_hex("50a6c61c3f7c2b37e72b0c047000dd4a"), 0};

SubSampleInfo single_encrypted_sub_sample = {
    // key 1, encrypted, 256b
    true, 1, true, false, wvcdm::a2bs_hex("E02562E04CD55351B14B3D748D36ED8E"),
    wvcdm::a2b_hex(
        "3b2cbde084973539329bd5656da22d20396249bf4a18a51c38c4743360cc9fea"
        "a1c78d53de1bd7e14dc5d256fd20a57178a98b83804258c239acd7aa38f2d7d2"
        "eca614965b3d22049e19e236fc1800e60965d8b36415677bf2f843d50a6943c4"
        "683c07c114a32f5e5fbc9939c483c3a1b2ecd3d82b554d649798866191724283"
        "f0ab082eba2da79aaca5c4eaf186f9ee9a0c568f621f705a578f30e4e2ef7b96"
        "5e14cc046ce6dbf272ee5558b098f332333e95fc879dea6c29bf34acdb649650"
        "f08201b9e649960f2493fd7677cc3abf5ae70e5445845c947ba544456b431646"
        "d95a133bff5f57614dda5e4446cd8837901d074149dadf4b775b5b07bb88ca20"),
    wvcdm::a2b_hex(
        "5a36c0b633b58faf22156d78fdfb608e54a8095788b2b0463ef78d030b4abf82"
        "eff34b8d9b7b6352e7d72de991b599662aa475da355033620152e2356ebfadee"
        "06172be9e1058fa177e223b9fdd191380cff53c3ea810c6fd852a1df4967b799"
        "415179a2276ec388ef763bab89605b9c6952c28dc8d6bf86b03fabbb46b392a3"
        "1dad15be602eeeeabb45070b3e25d6bb0217073b1fc44c9fe848594121fd6a91"
        "304d605e21f69615e1b57db18312b6b948725724b74e91d8aea7371e99532469"
        "1b358bdee873f1936b63efe83d190a53c2d21754d302d63ff285174023473755"
        "58b938c2e3ca4c2ce48942da97f9e45797f2c074ac6004734e93784a48af6160"),
    wvcdm::a2b_hex("4cca615fc013102892f91efee936639b"), 0};

SubSampleInfo switch_key_encrypted_sub_sample[2] = {
    // block 0, key 1, encrypted, 256b
    {true, 2, true, false, wvcdm::a2bs_hex("E02562E04CD55351B14B3D748D36ED8E"),
     wvcdm::a2b_hex(
         "3b2cbde084973539329bd5656da22d20396249bf4a18a51c38c4743360cc9fea"
         "a1c78d53de1bd7e14dc5d256fd20a57178a98b83804258c239acd7aa38f2d7d2"
         "eca614965b3d22049e19e236fc1800e60965d8b36415677bf2f843d50a6943c4"
         "683c07c114a32f5e5fbc9939c483c3a1b2ecd3d82b554d649798866191724283"
         "f0ab082eba2da79aaca5c4eaf186f9ee9a0c568f621f705a578f30e4e2ef7b96"
         "5e14cc046ce6dbf272ee5558b098f332333e95fc879dea6c29bf34acdb649650"
         "f08201b9e649960f2493fd7677cc3abf5ae70e5445845c947ba544456b431646"
         "d95a133bff5f57614dda5e4446cd8837901d074149dadf4b775b5b07bb88ca20"),
     wvcdm::a2b_hex(
         "5a36c0b633b58faf22156d78fdfb608e54a8095788b2b0463ef78d030b4abf82"
         "eff34b8d9b7b6352e7d72de991b599662aa475da355033620152e2356ebfadee"
         "06172be9e1058fa177e223b9fdd191380cff53c3ea810c6fd852a1df4967b799"
         "415179a2276ec388ef763bab89605b9c6952c28dc8d6bf86b03fabbb46b392a3"
         "1dad15be602eeeeabb45070b3e25d6bb0217073b1fc44c9fe848594121fd6a91"
         "304d605e21f69615e1b57db18312b6b948725724b74e91d8aea7371e99532469"
         "1b358bdee873f1936b63efe83d190a53c2d21754d302d63ff285174023473755"
         "58b938c2e3ca4c2ce48942da97f9e45797f2c074ac6004734e93784a48af6160"),
     wvcdm::a2b_hex("4cca615fc013102892f91efee936639b"), 0},
    // block 1, key 3, encrypted, 256b
    {true, 2, true, false, wvcdm::a2bs_hex("0065901A64A25899A5193664ABF9AF62"),
     wvcdm::a2b_hex(
         "337f294addb4c16d1015fd839e80314472432eda503bd0529422318bec7d2b34"
         "2b28d24b2c0bf999fd31711901a2b90e03373cb9553ffd4b2e6e655b80a39fe8"
         "61718220948f0031a37fe277f943409d09c83ff1c19fe8d601f5b4d139821750"
         "47170006db5f38cb84706a9beeaa455fca3b17d8de90c143eb36aaaac3f4670a"
         "7194064f4d59996c95992a3e6a848d4da8adddae3ad03c8d28110fda3e5c1d0a"
         "35d175c816481275a02d2da96c7fc313864ae076f03887309cdf00ca856bad28"
         "2146141964b7f7972e9b253b1fbed6d74ffedcfc51bb91fa78a602479b0b757f"
         "53a16cca15c381a4eab3034ee38e12280982d575fe3de23dd65cf8ba240daa88"),
     wvcdm::a2b_hex(
         "c397c1c9bc6782cd859e92f7158e3ff2a54ee984869582b942b400c22ebb6843"
         "7c50f999f73831fa12040f6aab607f57280189ff1db1ab1d0046ffaa55ce1790"
         "3baf0f9c983351b2ff15cc4f61f0f8db6922804e74a207e1e5baaeca67b427c7"
         "2dd7883ee8232041a9c4e56ccfb8bdc3016602c73fa8944e734ee34c41cf1a17"
         "b009b404fd924d23dfee1f494b5e374c9e87c2910de36826044bff89939a70d2"
         "47ff1a8a0baa7643026b8d9442fda69dde6802816ddd4b6e3b18f0a95e788d6d"
         "166ed7435ef663ef019b4438d3e203734eb95d68758e028f29cd623f35cde4bd"
         "edfea33ade378a92a356020bcf3fbba01c9ab16ad448ce6ebe708f768c6676a7"),
     wvcdm::a2b_hex("6d4ee851e563b951119cd33c52aadbf5"), 0}};

SubSampleInfo partial_single_encrypted_sub_sample = {
    // key 3, encrypted, 125b, offset 0
    true, 1, true, false, wvcdm::a2bs_hex("0065901A64A25899A5193664ABF9AF62"),
    wvcdm::a2b_hex(
        "337f294addb4c16d1015fd839e80314472432eda503bd0529422318bec7d2b34"
        "2b28d24b2c0bf999fd31711901a2b90e03373cb9553ffd4b2e6e655b80a39fe8"
        "61718220948f0031a37fe277f943409d09c83ff1c19fe8d601f5b4d139821750"
        "47170006db5f38cb84706a9beeaa455fca3b17d8de90c143eb36aaaac3"),
    wvcdm::a2b_hex(
        "c397c1c9bc6782cd859e92f7158e3ff2a54ee984869582b942b400c22ebb6843"
        "7c50f999f73831fa12040f6aab607f57280189ff1db1ab1d0046ffaa55ce1790"
        "3baf0f9c983351b2ff15cc4f61f0f8db6922804e74a207e1e5baaeca67b427c7"
        "2dd7883ee8232041a9c4e56ccfb8bdc3016602c73fa8944e734ee34c41"),
    wvcdm::a2b_hex("6d4ee851e563b951119cd33c52aadbf5"), 0};

SubSampleInfo partial_offset_single_encrypted_sub_sample = {
    // key 3, encrypted, 123b, offset 5
    true, 1, true, false, wvcdm::a2bs_hex("0065901A64A25899A5193664ABF9AF62"),
    wvcdm::a2b_hex(
        "97f39b919ba56f3c3a51ecdcd7318bc130f054320c74db3990f925"
        "054734c03ec79ee0da68938dc4f8c2d91e46ec2342ef24f9328294a9475f7ead"
        "8ad3e71db62d6328e826e4ab375f4796aa2bc8b9266551e3007fb3c253780293"
        "31fbc32ed29afcb9e7152cf072712c5a22c6b52d60e381eb53eeb58d36528746"),
    wvcdm::a2b_hex(
        "d36911b44f470ff05d152a7bc69ea6b68aa812cd3676964acb4597"
        "b518fe4b7ec0fe44469b1e4f8806922af9ac998d3e23349cea0e68f833564c15"
        "e49584f94ef16b7ab6cd2d0b152430f1fb4d7644a0f591980388ac02012d3d42"
        "73d6c9604517b1a622b66b8f4e8414e40b00351cc9859061bde810190c7b5df8"),
    wvcdm::a2b_hex("43ba341482212c70f79d81c0f4faef8a"), 5};

}  // namespace

namespace wvcdm {
class TestWvCdmClientPropertySet : public CdmClientPropertySet {
 public:
  TestWvCdmClientPropertySet()
      : use_privacy_mode_(false),
        is_session_sharing_enabled_(false),
        session_sharing_id_(0) {}
  virtual ~TestWvCdmClientPropertySet() {}

  virtual std::string security_level() const { return security_level_; }
  virtual std::vector<uint8_t> service_certificate() const {
    return service_certificate_;
  }
  virtual bool use_privacy_mode() const { return use_privacy_mode_; }
  bool is_session_sharing_enabled() const {
    return is_session_sharing_enabled_;
  }
  uint32_t session_sharing_id() const { return session_sharing_id_; }

  void set_security_level(const std::string& security_level) {
    if (!security_level.compare(QUERY_VALUE_SECURITY_LEVEL_L1) ||
        !security_level.compare(QUERY_VALUE_SECURITY_LEVEL_L3)) {
      security_level_ = security_level;
    }
  }
  void set_service_certificate(
      const std::vector<uint8_t>& service_certificate) {
    service_certificate_ = service_certificate;
  }
  void set_use_privacy_mode(bool use_privacy_mode) {
    use_privacy_mode_ = use_privacy_mode;
  }
  void set_session_sharing_mode(bool enable) {
    is_session_sharing_enabled_ = enable;
  }
  void set_session_sharing_id(uint32_t id) { session_sharing_id_ = id; }

 private:
  std::string security_level_;
  std::vector<uint8_t> service_certificate_;
  bool use_privacy_mode_;
  bool is_session_sharing_enabled_;
  uint32_t session_sharing_id_;
};

class TestWvCdmEventListener : public WvCdmEventListener {
 public:
  TestWvCdmEventListener() : WvCdmEventListener() {}
  virtual void onEvent(const CdmSessionId& id, CdmEventType event) {
    session_id_ = id;
    event_type_ = event;
  }
  CdmSessionId session_id() { return session_id_; }
  CdmEventType event_type() { return event_type_; }

 private:
  CdmSessionId session_id_;
  CdmEventType event_type_;
};

class WvCdmRequestLicenseTest : public testing::Test {
 public:
  WvCdmRequestLicenseTest() {}
  ~WvCdmRequestLicenseTest() {}

 protected:
  void GenerateKeyRequest(const std::string& key_system,
                          const std::string& init_data,
                          CdmLicenseType license_type) {
    wvcdm::CdmAppParameterMap app_parameters;
    std::string server_url;
    std::string key_set_id;
    EXPECT_EQ(wvcdm::KEY_MESSAGE,
              decryptor_.GenerateKeyRequest(session_id_, key_set_id, init_data,
                                            license_type, app_parameters,
                                            &key_msg_, &server_url));
    EXPECT_EQ(0u, server_url.size());
  }

  void GenerateRenewalRequest(const std::string& key_system,
                              CdmLicenseType license_type,
                              std::string* server_url) {
    // TODO application makes a license request, CDM will renew the license
    // when appropriate.
    std::string init_data;
    wvcdm::CdmAppParameterMap app_parameters;
    EXPECT_EQ(wvcdm::KEY_MESSAGE,
              decryptor_.GenerateKeyRequest(session_id_, key_set_id_, init_data,
                                            license_type, app_parameters,
                                            &key_msg_, server_url));
    // TODO(edwinwong, rfrias): Add tests cases for when license server url
    // is empty on renewal. Need appropriate key id at the server.
    EXPECT_NE(0u, server_url->size());
  }

  void GenerateKeyRelease(CdmKeySetId key_set_id) {
    CdmSessionId session_id;
    CdmInitData init_data;
    wvcdm::CdmAppParameterMap app_parameters;
    std::string server_url;
    EXPECT_EQ(wvcdm::KEY_MESSAGE,
              decryptor_.GenerateKeyRequest(session_id, key_set_id, init_data,
                                            kLicenseTypeRelease, app_parameters,
                                            &key_msg_, &server_url));
  }

  // Post a request and extract the drm message from the response
  std::string GetKeyRequestResponse(const std::string& server_url,
                                    const std::string& client_auth,
                                    int expected_response) {
    // Use secure connection and chunk transfer coding.
    UrlRequest url_request(server_url + client_auth, g_port,
                           g_use_secure_transfer, g_use_chunked_transfer);
    if (!url_request.is_connected()) {
      return "";
    }
    url_request.PostRequest(key_msg_);
    std::string message;
    int resp_bytes = url_request.GetResponse(&message);

    // Youtube server returns 400 for invalid message while play server returns
    // 500, so just test inequity here for invalid message
    int status_code = url_request.GetStatusCode(message);
    if (expected_response == 200) {
      EXPECT_EQ(200, status_code);
    }

    std::string drm_msg;
    if (200 == status_code) {
      LicenseRequest lic_request;
      lic_request.GetDrmMessage(message, drm_msg);
      LOGV("HTTP response body: (%u bytes)", drm_msg.size());
    }
    return drm_msg;
  }

  // Post a request and extract the signed provisioning message from
  // the HTTP response.
  std::string GetCertRequestResponse(const std::string& server_url,
                                     int expected_response) {
    // Use secure connection and chunk transfer coding.
    UrlRequest url_request(server_url, kDefaultHttpsPort, true, true);
    if (!url_request.is_connected()) {
      return "";
    }

    url_request.PostCertRequestInQueryString(key_msg_);
    std::string message;
    int resp_bytes = url_request.GetResponse(&message);
    LOGD("end %d bytes response dump", resp_bytes);

    // Youtube server returns 400 for invalid message while play server returns
    // 500, so just test inequity here for invalid message
    int status_code = url_request.GetStatusCode(message);
    if (expected_response == 200) {
      EXPECT_EQ(200, status_code);
    } else {
      EXPECT_NE(200, status_code);
    }
    return message;
  }

  void VerifyKeyRequestResponse(const std::string& server_url,
                                const std::string& client_auth,
                                std::string& init_data, bool is_renewal) {
    std::string resp = GetKeyRequestResponse(server_url, client_auth, 200);

    if (is_renewal) {
      // TODO application makes a license request, CDM will renew the license
      // when appropriate
      EXPECT_EQ(decryptor_.AddKey(session_id_, resp, &key_set_id_),
                wvcdm::KEY_ADDED);
    } else {
      EXPECT_EQ(decryptor_.AddKey(session_id_, resp, &key_set_id_),
                wvcdm::KEY_ADDED);
    }
  }

  wvcdm::WvContentDecryptionModule decryptor_;
  CdmKeyMessage key_msg_;
  CdmSessionId session_id_;
  CdmKeySetId key_set_id_;
};

class WvCdmDecryptionTest
    : public WvCdmRequestLicenseTest,
      public ::testing::WithParamInterface<SubSampleInfo*> {};

class WvCdmSessionSharingTest
    : public WvCdmRequestLicenseTest,
      public ::testing::WithParamInterface<bool> {};

TEST_F(WvCdmRequestLicenseTest, ProvisioningTest) {
  decryptor_.OpenSession(g_key_system, NULL, &session_id_);
  std::string provisioning_server_url;

  EXPECT_EQ(wvcdm::NO_ERROR, decryptor_.GetProvisioningRequest(
                                 &key_msg_, &provisioning_server_url));
  EXPECT_EQ(provisioning_server_url, g_config->provisioning_server_url());

  std::string response =
      GetCertRequestResponse(g_config->provisioning_test_server_url(), 200);
  EXPECT_NE(0, static_cast<int>(response.size()));
  EXPECT_EQ(wvcdm::NO_ERROR, decryptor_.HandleProvisioningResponse(response));
  decryptor_.CloseSession(session_id_);
}

TEST_F(WvCdmRequestLicenseTest, ProvisioningRetryTest) {
  decryptor_.OpenSession(g_key_system, NULL, &session_id_);
  std::string provisioning_server_url;

  EXPECT_EQ(wvcdm::NO_ERROR, decryptor_.GetProvisioningRequest(
                                 &key_msg_, &provisioning_server_url));
  EXPECT_EQ(provisioning_server_url, g_config->provisioning_server_url());

  EXPECT_EQ(wvcdm::NO_ERROR, decryptor_.GetProvisioningRequest(
                                 &key_msg_, &provisioning_server_url));
  EXPECT_EQ(provisioning_server_url, g_config->provisioning_server_url());

  std::string response =
      GetCertRequestResponse(g_config->provisioning_test_server_url(), 200);
  EXPECT_NE(0, static_cast<int>(response.size()));
  EXPECT_EQ(wvcdm::NO_ERROR, decryptor_.HandleProvisioningResponse(response));

  response =
      GetCertRequestResponse(g_config->provisioning_test_server_url(), 200);
  EXPECT_NE(0, static_cast<int>(response.size()));
  EXPECT_EQ(wvcdm::UNKNOWN_ERROR,
            decryptor_.HandleProvisioningResponse(response));
  decryptor_.CloseSession(session_id_);
}

TEST_F(WvCdmRequestLicenseTest, PropertySetTest) {
  TestWvCdmClientPropertySet property_set_L1;
  TestWvCdmClientPropertySet property_set_L3;
  TestWvCdmClientPropertySet property_set_Ln;
  CdmSessionId session_id_L1;
  CdmSessionId session_id_L3;
  CdmSessionId session_id_Ln;

  property_set_L1.set_security_level(QUERY_VALUE_SECURITY_LEVEL_L1);
  property_set_L1.set_use_privacy_mode(true);
  decryptor_.OpenSession(g_key_system, &property_set_L1, &session_id_L1);
  property_set_L3.set_security_level(QUERY_VALUE_SECURITY_LEVEL_L3);
  property_set_L3.set_use_privacy_mode(false);

  CdmResponseType sts = decryptor_.OpenSession(g_key_system, &property_set_L3,
                                               &session_id_L3);

  if (NEED_PROVISIONING == sts) {
    std::string provisioning_server_url;
    EXPECT_EQ(
        NO_ERROR,
        decryptor_.GetProvisioningRequest(&key_msg_, &provisioning_server_url));
    EXPECT_EQ(provisioning_server_url, g_config->provisioning_server_url());
    std::string response =
        GetCertRequestResponse(g_config->provisioning_test_server_url(), 200);
    EXPECT_NE(0, static_cast<int>(response.size()));
    EXPECT_EQ(NO_ERROR, decryptor_.HandleProvisioningResponse(response));
    EXPECT_EQ(NO_ERROR, decryptor_.OpenSession(g_key_system, &property_set_L3,
                                               &session_id_L3));
  } else {
    EXPECT_EQ(NO_ERROR, sts);
  }

  property_set_Ln.set_security_level("");
  decryptor_.OpenSession(g_key_system, &property_set_Ln, &session_id_Ln);

  std::string security_level = Properties::GetSecurityLevel(session_id_L1);
  EXPECT_TRUE(!security_level.compare(QUERY_VALUE_SECURITY_LEVEL_L1) ||
              !security_level.compare(QUERY_VALUE_SECURITY_LEVEL_L3));
  EXPECT_TRUE(Properties::UsePrivacyMode(session_id_L1));
  EXPECT_EQ(Properties::GetSecurityLevel(session_id_L3),
                                         QUERY_VALUE_SECURITY_LEVEL_L3);
  EXPECT_FALSE(Properties::UsePrivacyMode(session_id_L3));
  security_level = Properties::GetSecurityLevel(session_id_Ln);
  EXPECT_TRUE(security_level.empty() ||
              !security_level.compare(QUERY_VALUE_SECURITY_LEVEL_L3));
  decryptor_.CloseSession(session_id_L1);
  decryptor_.CloseSession(session_id_L3);
  decryptor_.CloseSession(session_id_Ln);
}

TEST_F(WvCdmRequestLicenseTest, ForceL3Test) {
  TestWvCdmClientPropertySet property_set;
  property_set.set_security_level(QUERY_VALUE_SECURITY_LEVEL_L3);

  File file;
  DeviceFiles handle;
  EXPECT_TRUE(handle.Init(&file, kSecurityLevelL3));
  EXPECT_TRUE(handle.DeleteAllFiles());

  EXPECT_EQ(NEED_PROVISIONING,
            decryptor_.OpenSession(g_key_system, &property_set, &session_id_));
  std::string provisioning_server_url;
  EXPECT_EQ(NO_ERROR,
            decryptor_.GetProvisioningRequest(&key_msg_,
                                              &provisioning_server_url));
  EXPECT_EQ(provisioning_server_url, g_config->provisioning_server_url());
  std::string response =
      GetCertRequestResponse(g_config->provisioning_test_server_url(), 200);
  EXPECT_NE(0, static_cast<int>(response.size()));
  EXPECT_EQ(NO_ERROR, decryptor_.HandleProvisioningResponse(response));

  EXPECT_EQ(NO_ERROR, decryptor_.OpenSession(g_key_system, &property_set,
                                             &session_id_));
  GenerateKeyRequest(g_key_system, g_key_id, kLicenseTypeStreaming);
  VerifyKeyRequestResponse(g_license_server, g_client_auth, g_key_id, false);
  decryptor_.CloseSession(session_id_);
}

TEST_F(WvCdmRequestLicenseTest, DISABLED_PrivacyModeTest) {
  TestWvCdmClientPropertySet property_set;

  property_set.set_use_privacy_mode(true);
  decryptor_.OpenSession(g_key_system, &property_set, &session_id_);

  GenerateKeyRequest(g_key_system, g_key_id, kLicenseTypeStreaming);
  std::string resp = GetKeyRequestResponse(g_license_server,
                                           g_client_auth, 200);
  EXPECT_EQ(decryptor_.AddKey(session_id_, resp, &key_set_id_),
            wvcdm::NEED_KEY);
  GenerateKeyRequest(g_key_system, g_key_id, kLicenseTypeStreaming);
  VerifyKeyRequestResponse(g_license_server, g_client_auth, g_key_id, false);
  decryptor_.CloseSession(session_id_);
}

TEST_F(WvCdmRequestLicenseTest, DISABLED_PrivacyModeWithServiceCertificateTest) {
  TestWvCdmClientPropertySet property_set;

  property_set.set_use_privacy_mode(true);
  property_set.set_service_certificate(a2b_hex(kServiceCertificate));
  decryptor_.OpenSession(g_key_system, &property_set, &session_id_);
  GenerateKeyRequest(g_key_system, g_key_id, kLicenseTypeStreaming);
  VerifyKeyRequestResponse(g_license_server, g_client_auth, g_key_id, false);
  decryptor_.CloseSession(session_id_);
}

TEST_P(WvCdmSessionSharingTest, SessionSharingTest) {
  bool enable_session_sharing = GetParam();

  TestWvCdmClientPropertySet property_set;
  property_set.set_session_sharing_mode(enable_session_sharing);

  decryptor_.OpenSession(g_key_system, &property_set, &session_id_);
  CdmSessionId gp_session_id_1 = session_id_;
  GenerateKeyRequest(g_key_system, g_key_id, kLicenseTypeStreaming);
  VerifyKeyRequestResponse(g_license_server, g_client_auth, g_key_id, false);

  // TODO(rfrias): Move content information to ConfigTestEnv
  std::string gp_client_auth2 =
      "?source=YOUTUBE&video_id=z3S_NhwueaM&oauth=ya.gtsqawidevine";
  std::string gp_key_id2 =
      wvcdm::a2bs_hex(
          "000000347073736800000000"                   // blob size and pssh
          "edef8ba979d64acea3c827dcd51d21ed00000014"   // Widevine system id
          "08011210bdf1cb4fffc6506b8b7945b0bd2917fb"); // pssh data

  decryptor_.OpenSession(g_key_system, &property_set, &session_id_);
  CdmSessionId gp_session_id_2 = session_id_;
  GenerateKeyRequest(g_key_system, gp_key_id2, kLicenseTypeStreaming);
  VerifyKeyRequestResponse(g_license_server, gp_client_auth2, gp_key_id2, false);

  SubSampleInfo* data = &single_encrypted_sub_sample;
  std::vector<uint8_t> decrypt_buffer(data->encrypt_data.size());
  CdmDecryptionParameters decryption_parameters(&data->key_id,
                                                &data->encrypt_data.front(),
                                                data->encrypt_data.size(),
                                                &data->iv,
                                                data->block_offset,
                                                &decrypt_buffer[0]);
  decryption_parameters.is_encrypted = data->is_encrypted;
  decryption_parameters.is_secure = data->is_secure;

  if (enable_session_sharing) {
    EXPECT_EQ(NO_ERROR, decryptor_.Decrypt(gp_session_id_2,
                                           decryption_parameters));
    EXPECT_TRUE(std::equal(data->decrypt_data.begin(), data->decrypt_data.end(),
                           decrypt_buffer.begin()));
  } else {
    EXPECT_EQ(NEED_KEY, decryptor_.Decrypt(gp_session_id_2,
                                           decryption_parameters));
  }

  decryptor_.CloseSession(gp_session_id_1);
  decryptor_.CloseSession(gp_session_id_2);
}

INSTANTIATE_TEST_CASE_P(Cdm, WvCdmSessionSharingTest, ::testing::Bool());

TEST_F(WvCdmRequestLicenseTest, BaseMessageTest) {
  decryptor_.OpenSession(g_key_system, NULL, &session_id_);
  GenerateKeyRequest(g_key_system, g_key_id, kLicenseTypeStreaming);
  GetKeyRequestResponse(g_license_server, g_client_auth, 200);
  decryptor_.CloseSession(session_id_);
}

TEST_F(WvCdmRequestLicenseTest, WrongMessageTest) {
  decryptor_.OpenSession(g_key_system, NULL, &session_id_);

  std::string wrong_message = wvcdm::a2bs_hex(g_wrong_key_id);
  GenerateKeyRequest(g_key_system, wrong_message, kLicenseTypeStreaming);
  GetKeyRequestResponse(g_license_server, g_client_auth, 500);
  decryptor_.CloseSession(session_id_);
}

TEST_F(WvCdmRequestLicenseTest, AddStreamingKeyTest) {
  decryptor_.OpenSession(g_key_system, NULL, &session_id_);
  GenerateKeyRequest(g_key_system, g_key_id, kLicenseTypeStreaming);
  VerifyKeyRequestResponse(g_license_server, g_client_auth, g_key_id, false);
  decryptor_.CloseSession(session_id_);
}

TEST_F(WvCdmRequestLicenseTest, AddKeyOfflineTest) {
  decryptor_.OpenSession(g_key_system, NULL, &session_id_);
  GenerateKeyRequest(g_key_system, g_key_id, kLicenseTypeOffline);
  VerifyKeyRequestResponse(g_license_server, g_client_auth, g_key_id, false);
  decryptor_.CloseSession(session_id_);
}

TEST_F(WvCdmRequestLicenseTest, RestoreOfflineKeyTest) {
  decryptor_.OpenSession(g_key_system, NULL, &session_id_);
  GenerateKeyRequest(g_key_system, g_key_id, kLicenseTypeOffline);
  VerifyKeyRequestResponse(g_license_server, g_client_auth, g_key_id, false);

  CdmKeySetId key_set_id = key_set_id_;
  EXPECT_FALSE(key_set_id_.empty());
  decryptor_.CloseSession(session_id_);

  session_id_.clear();
  decryptor_.OpenSession(g_key_system, NULL, &session_id_);
  EXPECT_EQ(wvcdm::KEY_ADDED, decryptor_.RestoreKey(session_id_, key_set_id));
  decryptor_.CloseSession(session_id_);
}

TEST_F(WvCdmRequestLicenseTest, ReleaseOfflineKeyTest) {
  decryptor_.OpenSession(g_key_system, NULL, &session_id_);
  GenerateKeyRequest(g_key_system, g_key_id, kLicenseTypeOffline);
  VerifyKeyRequestResponse(g_license_server, g_client_auth, g_key_id, false);

  CdmKeySetId key_set_id = key_set_id_;
  EXPECT_FALSE(key_set_id_.empty());
  decryptor_.CloseSession(session_id_);

  session_id_.clear();
  key_set_id_.clear();
  decryptor_.OpenSession(g_key_system, NULL, &session_id_);
  EXPECT_EQ(wvcdm::KEY_ADDED, decryptor_.RestoreKey(session_id_, key_set_id));
  decryptor_.CloseSession(session_id_);

  session_id_.clear();
  key_set_id_.clear();
  GenerateKeyRelease(key_set_id);
  key_set_id_ = key_set_id;
  VerifyKeyRequestResponse(g_license_server, g_client_auth, g_key_id, false);
}

TEST_F(WvCdmRequestLicenseTest, ExpiryOnReleaseOfflineKeyTest) {
  decryptor_.OpenSession(g_key_system, NULL, &session_id_);
  GenerateKeyRequest(g_key_system, g_key_id, kLicenseTypeOffline);
  VerifyKeyRequestResponse(g_license_server, g_client_auth, g_key_id, false);

  CdmKeySetId key_set_id = key_set_id_;
  EXPECT_FALSE(key_set_id_.empty());
  decryptor_.CloseSession(session_id_);

  session_id_.clear();
  key_set_id_.clear();
  decryptor_.OpenSession(g_key_system, NULL, &session_id_);
  CdmSessionId restore_session_id = session_id_;
  TestWvCdmEventListener listener;
  EXPECT_TRUE(decryptor_.AttachEventListener(restore_session_id, &listener));
  EXPECT_EQ(wvcdm::KEY_ADDED,
            decryptor_.RestoreKey(restore_session_id, key_set_id));

  session_id_.clear();
  key_set_id_.clear();
  EXPECT_TRUE(listener.session_id().size() == 0);
  GenerateKeyRelease(key_set_id);
  key_set_id_ = key_set_id;
  EXPECT_TRUE(listener.session_id().size() != 0);
  EXPECT_TRUE(listener.session_id().compare(restore_session_id) == 0);
  EXPECT_TRUE(listener.event_type() == LICENSE_EXPIRED_EVENT);
  VerifyKeyRequestResponse(g_license_server, g_client_auth, g_key_id, false);
  decryptor_.CloseSession(restore_session_id);
}

TEST_F(WvCdmRequestLicenseTest, StreamingLicenseRenewal) {
  decryptor_.OpenSession(g_key_system, NULL, &session_id_);
  GenerateKeyRequest(g_key_system, g_key_id, kLicenseTypeStreaming);
  VerifyKeyRequestResponse(g_license_server, g_client_auth, g_key_id, false);

  std::string license_server;
  GenerateRenewalRequest(g_key_system, kLicenseTypeStreaming, &license_server);
  if (license_server.empty())
    license_server = g_license_server;
  VerifyKeyRequestResponse(license_server, g_client_auth, g_key_id, true);
  decryptor_.CloseSession(session_id_);
}

TEST_F(WvCdmRequestLicenseTest, OfflineLicenseRenewal) {
  decryptor_.OpenSession(g_key_system, NULL, &session_id_);
  GenerateKeyRequest(g_key_system, g_key_id, kLicenseTypeOffline);
  VerifyKeyRequestResponse(g_license_server, g_client_auth, g_key_id, false);

  std::string license_server;
  GenerateRenewalRequest(g_key_system, kLicenseTypeOffline, &license_server);
  if (license_server.empty())
    license_server = g_license_server;
  VerifyKeyRequestResponse(license_server, g_client_auth, g_key_id, true);
  decryptor_.CloseSession(session_id_);
}

TEST_F(WvCdmRequestLicenseTest, QuerySessionStatus) {
  // Test that the global value is returned when no properties are modifying it.
  CdmQueryMap system_query_info;
  CdmQueryMap::iterator system_itr;
  ASSERT_EQ(wvcdm::NO_ERROR, decryptor_.QueryStatus(&system_query_info));
  system_itr = system_query_info.find(wvcdm::QUERY_KEY_SECURITY_LEVEL);
  ASSERT_TRUE(system_itr != system_query_info.end());

  decryptor_.OpenSession(g_key_system, NULL, &session_id_);
  CdmQueryMap unmodified_query_info;
  CdmQueryMap::iterator unmodified_itr;
  ASSERT_EQ(wvcdm::NO_ERROR,
            decryptor_.QuerySessionStatus(session_id_, &unmodified_query_info));
  unmodified_itr = unmodified_query_info.find(wvcdm::QUERY_KEY_SECURITY_LEVEL);
  ASSERT_TRUE(unmodified_itr != unmodified_query_info.end());
  EXPECT_EQ(system_itr->second, unmodified_itr->second);
  decryptor_.CloseSession(session_id_);

  // Test that L3 is returned when properties downgrade security.
  TestWvCdmClientPropertySet property_set_L3;
  property_set_L3.set_security_level(QUERY_VALUE_SECURITY_LEVEL_L3);

  decryptor_.OpenSession(g_key_system, &property_set_L3, &session_id_);
  CdmQueryMap modified_query_info;
  CdmQueryMap::iterator modified_itr;
  ASSERT_EQ(wvcdm::NO_ERROR,
            decryptor_.QuerySessionStatus(session_id_, &modified_query_info));
  modified_itr = modified_query_info.find(wvcdm::QUERY_KEY_SECURITY_LEVEL);
  ASSERT_TRUE(modified_itr != modified_query_info.end());
  EXPECT_EQ(QUERY_VALUE_SECURITY_LEVEL_L3, modified_itr->second);
  decryptor_.CloseSession(session_id_);

}

TEST_F(WvCdmRequestLicenseTest, QueryKeyStatus) {
  decryptor_.OpenSession(g_key_system, NULL, &session_id_);
  GenerateKeyRequest(g_key_system, g_key_id, kLicenseTypeStreaming);
  VerifyKeyRequestResponse(g_license_server, g_client_auth, g_key_id, false);

  CdmQueryMap query_info;
  CdmQueryMap::iterator itr;
  EXPECT_EQ(wvcdm::NO_ERROR,
            decryptor_.QueryKeyStatus(session_id_, &query_info));

  itr = query_info.find(wvcdm::QUERY_KEY_LICENSE_TYPE);
  ASSERT_TRUE(itr != query_info.end());
  EXPECT_EQ(wvcdm::QUERY_VALUE_STREAMING, itr->second);
  itr = query_info.find(wvcdm::QUERY_KEY_PLAY_ALLOWED);
  ASSERT_TRUE(itr != query_info.end());
  EXPECT_EQ(wvcdm::QUERY_VALUE_TRUE, itr->second);
  itr = query_info.find(wvcdm::QUERY_KEY_PERSIST_ALLOWED);
  ASSERT_TRUE(itr != query_info.end());
  EXPECT_EQ(wvcdm::QUERY_VALUE_FALSE, itr->second);
  itr = query_info.find(wvcdm::QUERY_KEY_RENEW_ALLOWED);
  ASSERT_TRUE(itr != query_info.end());
  EXPECT_EQ(wvcdm::QUERY_VALUE_TRUE, itr->second);

  int64_t remaining_time;
  std::istringstream ss;
  itr = query_info.find(wvcdm::QUERY_KEY_LICENSE_DURATION_REMAINING);
  ASSERT_TRUE(itr != query_info.end());
  ss.str(itr->second);
  ASSERT_TRUE(ss >> remaining_time);
  EXPECT_LT(0, remaining_time);
  itr = query_info.find(wvcdm::QUERY_KEY_PLAYBACK_DURATION_REMAINING);
  ASSERT_TRUE(itr != query_info.end());
  ss.clear();
  ss.str(itr->second);
  ASSERT_TRUE(ss >> remaining_time);
  EXPECT_LT(0, remaining_time);

  itr = query_info.find(wvcdm::QUERY_KEY_RENEWAL_SERVER_URL);
  ASSERT_TRUE(itr != query_info.end());
  EXPECT_LT(0u, itr->second.size());

  decryptor_.CloseSession(session_id_);
}

TEST_F(WvCdmRequestLicenseTest, QueryStatus) {
  CdmQueryMap query_info;
  CdmQueryMap::iterator itr;
  EXPECT_EQ(wvcdm::NO_ERROR, decryptor_.QueryStatus(&query_info));

  itr = query_info.find(wvcdm::QUERY_KEY_SECURITY_LEVEL);
  ASSERT_TRUE(itr != query_info.end());
  EXPECT_EQ(2u, itr->second.size());
  EXPECT_EQ(wvcdm::QUERY_VALUE_SECURITY_LEVEL_L3.at(0), itr->second.at(0));

  itr = query_info.find(wvcdm::QUERY_KEY_DEVICE_ID);
  ASSERT_TRUE(itr != query_info.end());
  EXPECT_GT(itr->second.size(), 0u);

  itr = query_info.find(wvcdm::QUERY_KEY_SYSTEM_ID);
  ASSERT_TRUE(itr != query_info.end());
  std::istringstream ss(itr->second);
  uint32_t system_id;
  EXPECT_TRUE(ss >> system_id);
  EXPECT_TRUE(ss.eof());

  itr = query_info.find(wvcdm::QUERY_KEY_PROVISIONING_ID);
  ASSERT_TRUE(itr != query_info.end());
  EXPECT_EQ(16u, itr->second.size());
}

TEST_F(WvCdmRequestLicenseTest, QueryKeyControlInfo) {
  decryptor_.OpenSession(g_key_system, NULL, &session_id_);
  GenerateKeyRequest(g_key_system, g_key_id, kLicenseTypeStreaming);
  VerifyKeyRequestResponse(g_license_server, g_client_auth, g_key_id, false);

  CdmQueryMap query_info;
  CdmQueryMap::iterator itr;
  EXPECT_EQ(wvcdm::NO_ERROR,
            decryptor_.QueryKeyControlInfo(session_id_, &query_info));

  uint32_t oem_crypto_session_id;
  itr = query_info.find(wvcdm::QUERY_KEY_OEMCRYPTO_SESSION_ID);
  ASSERT_TRUE(itr != query_info.end());
  std::istringstream ss;
  ss.str(itr->second);
  EXPECT_TRUE(ss >> oem_crypto_session_id);

  decryptor_.CloseSession(session_id_);
}

TEST_F(WvCdmRequestLicenseTest, SecurityLevelPathBackwardCompatibility) {
  CdmQueryMap query_info;
  CdmQueryMap::iterator itr;
  EXPECT_EQ(wvcdm::NO_ERROR, decryptor_.QueryStatus(&query_info));
  itr = query_info.find(wvcdm::QUERY_KEY_SECURITY_LEVEL);
  ASSERT_TRUE(itr != query_info.end());
  EXPECT_EQ(2u, itr->second.size());
  EXPECT_TRUE(itr->second.compare(wvcdm::QUERY_VALUE_SECURITY_LEVEL_L3) == 0 ||
              itr->second.compare(wvcdm::QUERY_VALUE_SECURITY_LEVEL_L1) == 0);

  CdmSecurityLevel security_level =
      (itr->second.compare(wvcdm::QUERY_VALUE_SECURITY_LEVEL_L1) == 0)
          ? kSecurityLevelL1
          : kSecurityLevelL3;

  std::string base_path;
  EXPECT_TRUE(Properties::GetDeviceFilesBasePath(security_level, &base_path));

  std::vector<std::string> security_dirs;
  EXPECT_TRUE(Properties::GetSecurityLevelDirectories(&security_dirs));
  size_t pos = std::string::npos;
  for (size_t i = 0; i < security_dirs.size(); i++) {
    pos = base_path.rfind(security_dirs[i]);
    if (std::string::npos != pos)
      break;
  }

  EXPECT_NE(std::string::npos, pos);
  std::string old_base_path(base_path, 0, pos);
  File file;
  file.Remove(old_base_path);

  decryptor_.OpenSession(g_key_system, NULL, &session_id_);
  std::string provisioning_server_url;
  EXPECT_EQ(wvcdm::NO_ERROR, decryptor_.GetProvisioningRequest(
                                 &key_msg_, &provisioning_server_url));
  EXPECT_EQ(provisioning_server_url, g_config->provisioning_server_url());
  std::string response =
      GetCertRequestResponse(g_config->provisioning_test_server_url(), 200);
  EXPECT_NE(0, static_cast<int>(response.size()));
  EXPECT_EQ(wvcdm::NO_ERROR, decryptor_.HandleProvisioningResponse(response));
  decryptor_.CloseSession(session_id_);

  decryptor_.OpenSession(g_key_system, NULL, &session_id_);
  GenerateKeyRequest(g_key_system, g_key_id, kLicenseTypeOffline);
  VerifyKeyRequestResponse(g_license_server, g_client_auth, g_key_id, false);
  CdmKeySetId key_set_id = key_set_id_;
  EXPECT_FALSE(key_set_id_.empty());
  decryptor_.CloseSession(session_id_);

  std::vector<std::string> files;
  EXPECT_TRUE(file.List(base_path, &files));
  EXPECT_TRUE(2u == files.size() || 3u == files.size());

  for (size_t i = 0; i < files.size(); ++i) {
    std::string from = base_path + files[i];
    if (file.IsRegularFile(from)) {
      std::string to = old_base_path + files[i];
      EXPECT_TRUE(file.Copy(from, to));
    }
  }
  EXPECT_TRUE(file.Remove(base_path));

  // Setup complete to earlier version (non-security level based) path.
  // Restore persistent license, retrieve L1, L3 streaming licenses to verify
  session_id_.clear();
  decryptor_.OpenSession(g_key_system, NULL, &session_id_);
  EXPECT_EQ(wvcdm::KEY_ADDED, decryptor_.RestoreKey(session_id_, key_set_id));
  decryptor_.CloseSession(session_id_);

  decryptor_.OpenSession(g_key_system, NULL, &session_id_);
  GenerateKeyRequest(g_key_system, g_key_id, kLicenseTypeStreaming);
  VerifyKeyRequestResponse(g_license_server, g_client_auth, g_key_id, false);
  decryptor_.CloseSession(session_id_);

  TestWvCdmClientPropertySet property_set;
  property_set.set_security_level(QUERY_VALUE_SECURITY_LEVEL_L3);

  EXPECT_EQ(NO_ERROR,
            decryptor_.OpenSession(g_key_system, &property_set, &session_id_));

  wvcdm::CdmAppParameterMap app_parameters;
  std::string server_url;
  EXPECT_EQ(wvcdm::NEED_PROVISIONING,
            decryptor_.GenerateKeyRequest(session_id_, key_set_id, g_key_id,
                                          kLicenseTypeStreaming, app_parameters,
                                          &key_msg_, &server_url));
  EXPECT_EQ(NO_ERROR,
            decryptor_.GetProvisioningRequest(&key_msg_,
                                              &provisioning_server_url));
  EXPECT_EQ(provisioning_server_url, g_config->provisioning_server_url());
  response =
      GetCertRequestResponse(g_config->provisioning_test_server_url(), 200);
  EXPECT_NE(0, static_cast<int>(response.size()));
  EXPECT_EQ(NO_ERROR, decryptor_.HandleProvisioningResponse(response));

  EXPECT_EQ(NO_ERROR, decryptor_.OpenSession(g_key_system, &property_set,
                                             &session_id_));
  GenerateKeyRequest(g_key_system, g_key_id, kLicenseTypeStreaming);
  VerifyKeyRequestResponse(g_license_server, g_client_auth, g_key_id, false);
  decryptor_.CloseSession(session_id_);
}

TEST_P(WvCdmDecryptionTest, DecryptionTest) {
  SubSampleInfo* data = GetParam();
  decryptor_.OpenSession(g_key_system, NULL, &session_id_);
  if (data->retrieve_key) {
    GenerateKeyRequest(g_key_system, g_key_id, kLicenseTypeStreaming);
    VerifyKeyRequestResponse(g_license_server, g_client_auth, g_key_id, false);
  }

  for (size_t i = 0; i < data->num_of_subsamples; i++) {
    std::vector<uint8_t> decrypt_buffer((data + i)->encrypt_data.size());
    CdmDecryptionParameters decryption_parameters(
        &(data + i)->key_id, &(data + i)->encrypt_data.front(),
        (data + i)->encrypt_data.size(), &(data + i)->iv,
        (data + i)->block_offset, &decrypt_buffer[0]);
    decryption_parameters.is_encrypted = (data + i)->is_encrypted;
    decryption_parameters.is_secure = (data + i)->is_secure;
    EXPECT_EQ(NO_ERROR, decryptor_.Decrypt(session_id_, decryption_parameters));

    EXPECT_TRUE(std::equal((data + i)->decrypt_data.begin(),
                           (data + i)->decrypt_data.end(),
                           decrypt_buffer.begin()));
  }
  decryptor_.CloseSession(session_id_);
}

INSTANTIATE_TEST_CASE_P(
    Cdm, WvCdmDecryptionTest,
    ::testing::Values(&clear_sub_sample, &clear_sub_sample_no_key,
                      &single_encrypted_sub_sample,
                      &switch_key_encrypted_sub_sample[0],
                      &partial_single_encrypted_sub_sample));

TEST_F(WvCdmRequestLicenseTest, DISABLED_OfflineLicenseDecryptionTest) {
  decryptor_.OpenSession(g_key_system, NULL, &session_id_);
  GenerateKeyRequest(g_key_system, g_key_id, kLicenseTypeOffline);
  VerifyKeyRequestResponse(g_license_server, g_client_auth, g_key_id, false);

  /*
    // key 1, encrypted, 256b
    DecryptionData data;
    data.is_encrypted = true;
    data.is_secure = false;
    data.key_id = wvcdm::a2bs_hex("30313233343536373839414243444546");
    data.encrypt_data = wvcdm::a2b_hex(
        "b6d7d2430aa82b1cb8bd32f02e1f3b2a8d84f9eddf935ced5a6a98022cbb4561"
        "8346a749fdb336858a64d7169fd0aa898a32891d14c24bed17fdc17fd62b8771"
        "a8e22e9f093fa0f2aacd293d471b8e886d5ed8d0998ab2fde2d908580ff88c93"
        "c0f0bbc14867267b3a3955bb6e7d05fca734a3aec3463d786d555cad83536ebe"
        "4496d934d40df2aba5aea98c1145a2890879568ae31bb8a85d74714a4ad75785"
        "7488523e697f5fd370eac746d56990a81cc76a178e3d6d65743520cdbc669412"
        "9e73b86214256c67430cf78662346cab3e2bdd6f095dddf75b7fb3868c5ff5ff"
        "3e1bbf08d456532ffa9df6e21a8bb2664c2d2a6d47ee78f9a6d53b2f2c8c087c");
    data.iv = wvcdm::a2b_hex("86856b9409743ca107b043e82068c7b6");
    data.block_offset = 0;
    data.decrypt_data = wvcdm::a2b_hex(
        "cc4a7fed8c5ac6e316e45317805c43e6d62a383ad738219c65e7a259dc12b46a"
        "d50a3f8ce2facec8eeadff9cfa6b649212b88602b41f6d4c510c05af07fd523a"
        "e7032634d9f8db5dd652d35f776376c5fc56e7031ed7cb28b72427fd4b367b6d"
        "8c4eb6e46ed1249de5d24a61aeb08ebd60984c10581042ca8b0ef6bc44ec34a0"
        "d4a77d68125c9bb1ace6f650e8716540f5b20d6482f7cfdf1b57a9ee9802160c"
        "a632ce42934347410abc61bb78fba11b093498572de38bca96101ecece455e3b"
        "5fef6805c44a2609cf97ce0dac7f15695c8058c590eda517f845108b90dfb29c"
        "e73f3656000399f2fd196bc6fc225f3a7b8f578237751fd485ff070b5289e5cf");

    std::vector<uint8_t> decrypt_buffer;
    size_t encrypt_length = data.encrypt_data.size();
    decrypt_buffer.resize(encrypt_length);

    EXPECT_EQ(NO_ERROR, decryptor_.Decrypt(session_id_,
                                           data.is_encrypted,
                                           data.is_secure,
                                           data.key_id,
                                           &data.encrypt_data.front(),
                                           encrypt_length,
                                           data.iv,
                                           data.block_offset,
                                           &decrypt_buffer.front(),
                                           0));

    EXPECT_TRUE(std::equal(data.decrypt_data.begin(), data.decrypt_data.end(),
        decrypt_buffer.begin()));
  */
  decryptor_.CloseSession(session_id_);
}

TEST_F(WvCdmRequestLicenseTest, DISABLED_RestoreOfflineLicenseDecryptionTest) {
  decryptor_.OpenSession(g_key_system, NULL, &session_id_);
  GenerateKeyRequest(g_key_system, g_key_id, kLicenseTypeOffline);
  VerifyKeyRequestResponse(g_license_server, g_client_auth, g_key_id, false);
  CdmKeySetId key_set_id = key_set_id_;
  EXPECT_FALSE(key_set_id_.empty());
  decryptor_.CloseSession(session_id_);

  session_id_.clear();
  decryptor_.OpenSession(g_key_system, NULL, &session_id_);
  EXPECT_EQ(wvcdm::KEY_ADDED, decryptor_.RestoreKey(session_id_, key_set_id));
  /*
    // key 1, encrypted, 256b
    DecryptionData data;
    data.is_encrypted = true;
    data.is_secure = false;
    data.key_id = wvcdm::a2bs_hex("30313233343536373839414243444546");
    data.encrypt_data = wvcdm::a2b_hex(
        "b6d7d2430aa82b1cb8bd32f02e1f3b2a8d84f9eddf935ced5a6a98022cbb4561"
        "8346a749fdb336858a64d7169fd0aa898a32891d14c24bed17fdc17fd62b8771"
        "a8e22e9f093fa0f2aacd293d471b8e886d5ed8d0998ab2fde2d908580ff88c93"
        "c0f0bbc14867267b3a3955bb6e7d05fca734a3aec3463d786d555cad83536ebe"
        "4496d934d40df2aba5aea98c1145a2890879568ae31bb8a85d74714a4ad75785"
        "7488523e697f5fd370eac746d56990a81cc76a178e3d6d65743520cdbc669412"
        "9e73b86214256c67430cf78662346cab3e2bdd6f095dddf75b7fb3868c5ff5ff"
        "3e1bbf08d456532ffa9df6e21a8bb2664c2d2a6d47ee78f9a6d53b2f2c8c087c");
    data.iv = wvcdm::a2b_hex("86856b9409743ca107b043e82068c7b6");
    data.block_offset = 0;
    data.decrypt_data = wvcdm::a2b_hex(
        "cc4a7fed8c5ac6e316e45317805c43e6d62a383ad738219c65e7a259dc12b46a"
        "d50a3f8ce2facec8eeadff9cfa6b649212b88602b41f6d4c510c05af07fd523a"
        "e7032634d9f8db5dd652d35f776376c5fc56e7031ed7cb28b72427fd4b367b6d"
        "8c4eb6e46ed1249de5d24a61aeb08ebd60984c10581042ca8b0ef6bc44ec34a0"
        "d4a77d68125c9bb1ace6f650e8716540f5b20d6482f7cfdf1b57a9ee9802160c"
        "a632ce42934347410abc61bb78fba11b093498572de38bca96101ecece455e3b"
        "5fef6805c44a2609cf97ce0dac7f15695c8058c590eda517f845108b90dfb29c"
        "e73f3656000399f2fd196bc6fc225f3a7b8f578237751fd485ff070b5289e5cf");

    std::vector<uint8_t> decrypt_buffer;
    size_t encrypt_length = data.encrypt_data.size();
    decrypt_buffer.resize(encrypt_length);

    EXPECT_EQ(NO_ERROR, decryptor_.Decrypt(session_id_,
                                           data.is_encrypted,
                                           data.is_secure,
                                           data.key_id,
                                           &data.encrypt_data.front(),
                                           encrypt_length,
                                           data.iv,
                                           data.block_offset,
                                           &decrypt_buffer.front(),
                                           0));

    EXPECT_TRUE(std::equal(data.decrypt_data.begin(), data.decrypt_data.end(),
        decrypt_buffer.begin()));
  */
  decryptor_.CloseSession(session_id_);
}

// TODO(rfrias, edwinwong): pending L1 OEMCrypto due to key block handling
/*
TEST_F(WvCdmRequestLicenseTest, KeyControlBlockDecryptionTest) {
  decryptor_.OpenSession(g_key_system, &session_id_);
  GenerateKeyRequest(g_key_system, g_key_id, kLicenseTypeStreaming);
  VerifyKeyRequestResponse(g_license_server, g_client_auth, g_key_id, false);

  DecryptionData data;

  // block 4, key 2, encrypted
  data.is_encrypted = true;
  data.is_secure = false;
  data.key_id = wvcdm::a2bs_hex("0915007CAA9B5931B76A3A85F046523E");
  data.encrypt_data = wvcdm::a2b_hex(
      "6758ac1c6ccf5d08479e3bfc62bbc0fd154aff4415aa7ed53d89e3983248d117"
      "ab5137ae7cedd9f9d7321d4cf35a7013237afbcc2d893d1d928efa94e9f7e2ed"
      "1855463cf75ff07ecc0246b90d0734f42d98aeea6a0a6d2618a8339bd0aca368"
      "4fb4a4670c0385e5bd5de9e2d8b9226851b8f8955adfbab968793b46fd152f5e"
      "e608467bb2695836f8f76c32731f5e208176d05e4b07020d58f6282c477f3840"
      "b8079c02e8bd1d03191d190cc505ddfbb2e9bacc794534c91fe409d62f5389b9"
      "35ed66134bd30f09f8da9dbfe6b8cf53d13cae34dae6e89109216e3a02233d5c"
      "2f66aef74313aae4a99b654b485b5cc207b2dc8d44a8b99a4dc196a9820eccef");
  data.iv = wvcdm::a2b_hex("c8f2d133ec357fe727cd233b3bfa755f");
  data.block_offset = 0;
  data.decrypt_data = wvcdm::a2b_hex(
      "34bab89185f1be990dfc454410c7c9093d008bc783908838b02a65b26db28759"
      "dca9dc5f117b3c8c3898358722d1b4c490e5a5d168ba0f9f8a3d4371b8fd1057"
      "2d6dd65f3f9d1850de8d76dc71bd6dc6c23da4e1223fcc3e47162033a6f82890"
      "e2bd6e9d6ddbe453830afc89064ed18078c786f8f746fcbafd88e83e7160cce5"
      "62fa7a7d699ef8421bda020d242ae4f61a786213b707c3b17b83d77510f9a07e"
      "d9d7e47d8f8fa2aff86eb26d61ddf384a27513e3facf6b1f5fe6c0d063b8856c"
      "c486d930393ea79ba73ba293eda39059e2ce9ee7bd5d31ab11f35e55dc35dfe0"
      "ea5e2ec684014852add6e29ce7d88a1595641ae4c0dd10155526b5a87560ec9d");

  std::vector<uint8_t> decrypt_buffer;
  size_t encrypt_length = data[i].encrypt_data.size();
  decrypt_buffer.resize(encrypt_length);

  EXPECT_EQ(NO_ERROR, decryptor_.Decrypt(session_id_,
                                         data.is_encrypted,
                                         data.is_secure,
                                         data.key_id,
                                         &data.encrypt_data.front(),
                                         encrypt_length,
                                         data.iv,
                                         data.block_offset,
                                         &decrypt_buffer.front()));

    EXPECT_TRUE(std::equal(data.decrypt_data.begin(),
        data.decrypt_data.end(),
        decrypt_buffer.begin()));
  }
  decryptor_.CloseSession(session_id_);
}
*/
}  // namespace wvcdm

void show_menu(char* prog_name) {
  std::cout << std::endl;
  std::cout << "usage: " << prog_name << " [options]" << std::endl << std::endl;
  std::cout << "  enclose multiple arguments in '' when using adb shell"
            << std::endl;
  std::cout << "  e.g. adb shell '" << prog_name << " --server=\"url\"'"
            << std::endl;
  std::cout << "   or  adb shell '" << prog_name << " -u\"url\"'"
            << std::endl << std::endl;

  std::cout << std::setw(35) << std::left << "  -c/--chunked_transfer";
  std::cout << "specifies chunked transfer encoding in request"
            << std::endl << std::endl;

  std::cout << std::setw(35) << std::left << "  -f/--use_full_path";
  std::cout << "specify server url is not a proxy server" << std::endl;
  std::cout << std::endl;

  std::cout << std::setw(35) << std::left
            << "  -i/--license_server_id=<gp/cp>";
  std::cout << "specifies which default server settings to use: " << std::endl;
  std::cout << std::setw(35) << std::left << " ";
  std::cout << "gp (case sensitive) for GooglePlay server" << std::endl;
  std::cout << std::setw(35) << std::left << " ";
  std::cout << "cp (case sensitive) for Youtube Content Protection server"
      << std::endl << std::endl;

  std::cout << std::setw(35) << std::left << "  -k/--keyid=<key_id>";
  std::cout << "configure the key id or pssh, in hex format"
            << std::endl << std::endl;

  std::cout << std::setw(35) << std::left
            << "  -p/--port=<port>";
  std::cout << "specifies the connection port" << std::endl << std::endl;

  std::cout << std::setw(35) << std::left
            << "  -s/--secure_transfer";
  std::cout << "use https transfer protocol" << std::endl << std::endl;

  std::cout << std::setw(35) << std::left
            << "  -u/--server=<server_url>";
  std::cout
      << "configure the license server url, please include http[s] in the url"
      << std::endl << std::endl;
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);

  bool show_usage = false;
  static const struct option long_options[] = {
    { "chunked_transfer", no_argument, NULL, 'c' },
    { "keyid", required_argument, NULL, 'k' },
    { "license_server_id", required_argument, NULL, 'i' },
    { "license_server_url", required_argument, NULL, 'u' },
    { "port", required_argument, NULL, 'p' },
    { "secure_transfer", no_argument, NULL, 's' },
    { "use_full_path", no_argument, NULL, 'f' },
    { NULL, 0, NULL, '\0' }
  };

  int option_index = 0;
  int opt = 0;
  while ((opt = getopt_long(argc, argv, "cfi:k:p:su:", long_options,
                            &option_index)) != -1) {
    switch (opt) {
      case 'c': {
        g_use_chunked_transfer = true;
        break;
      }
      case 'f': {
        g_use_full_path = true;
        break;
      }
      case 'i': {
        std::string license_id(optarg);
        if (!license_id.compare("gp")) {
          g_license_server_id = wvcdm::kGooglePlayServer;
        } else if (!license_id.compare("cp")) {
          g_license_server_id = wvcdm::kYouTubeContentProtectionServer;
        } else {
          std::cout << "Invalid license server id" << optarg << std::endl;
          show_usage = true;
        }
        break;
      }
      case 'k': {
        g_key_id.clear();
        g_key_id.assign(optarg);
        break;
      }
      case 'p': {
        g_port.clear();
        g_port.assign(optarg);
        break;
      }
      case 's': {
        g_use_secure_transfer = true;
        break;
      }
      case 'u': {
        g_license_server.clear();
        g_license_server.assign(optarg);
        break;
      }
      case '?': {
        show_usage = true;
        break;
      }
    }
  }

  if (show_usage) {
    show_menu(argv[0]);
    return 0;
  }

  g_config = new wvcdm::ConfigTestEnv(g_license_server_id);
  g_client_auth.assign(g_config->client_auth());
  g_key_system.assign(g_config->key_system());
  g_wrong_key_id.assign(g_config->wrong_key_id());

  // The following variables are configurable through command line
  // options. If the command line arguments are absent, use the settings
  // in license_servers[] pointed to by g_config.
  if (g_key_id.empty()) {
    g_key_id.assign(g_config->key_id());
  }
  if (g_license_server.empty()) {
    g_license_server.assign(g_config->license_server());
  }
  if (g_port.empty()) {
    g_port.assign(g_config->port());
  }
  if (!g_use_chunked_transfer) {
    g_use_chunked_transfer = g_config->use_chunked_transfer();
  }
  if (!g_use_secure_transfer) {
    g_use_secure_transfer = g_config->use_secure_transfer();
  }

  // Displays server url, port and key Id being used
  std::cout << std::endl;
  std::cout << "Server: " << g_license_server << std::endl;
  std::cout << "Port: " << g_port << std::endl;
  std::cout << "KeyID: " << g_key_id << std::endl << std::endl;

  g_key_id = wvcdm::a2bs_hex(g_key_id);
  g_config->set_license_server(g_license_server);
  g_config->set_port(g_port);
  g_config->set_key_id(g_key_id);

  int status = RUN_ALL_TESTS();
  delete g_config;
  return status;
}
