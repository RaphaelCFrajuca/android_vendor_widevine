// Copyright 2013 Google Inc. All Rights Reserved.

#include <errno.h>
#include <getopt.h>

#if defined(CHROMIUM_BUILD)
#include "base/at_exit.h"
#include "base/message_loop.h"
#endif
#include "cdm_engine.h"
#include "config_test_env.h"
#include "gtest/gtest.h"
#include "license_request.h"
#include "log.h"
#include "properties.h"
#include "scoped_ptr.h"
#include "string_conversions.h"
#include "url_request.h"
#include "wv_cdm_types.h"

namespace {
// Default license server, can be configured using --server command line option
// Default key id (pssh), can be configured using --keyid command line option
std::string g_client_auth;
wvcdm::KeyId g_key_id;
wvcdm::CdmKeySystem g_key_system;
std::string g_license_server;
std::string g_port;
wvcdm::KeyId g_wrong_key_id;
int g_use_full_path = 0;  // cannot use boolean in getopt_long

// This is the RSA certificate from the provisioning server.  The client
// sends this certificate to a license server as verification in the
// provisioning test case.
static wvcdm::CdmProvisioningResponse kValidJsonProvisioningResponse =
  "{\"signedResponse\": {"
  "\"message\": \"CrAJYTyIdLPiA2jBzMskbE_gFQj69wv23VlJ2e3MBKtK4nJwKyNYGyyluqKo"
  "TP751tvoADf86iLrf73mEzF58eSlaOjCpJRf2R3dojbNeSTy3JICmCc8vKtMjZRX9QWTvJbq_cg"
  "yMB8FQC8enuYhOaw1yJDYyCFHgik34NrUVUfmvaKKdSKQimqAZmjXi6P0znAn-XdPtz2xJVRxZp"
  "NH3QCD1bGcH_O1ercBW2JwF9KNalKFsxQrBhIwvyx-q-Ah4vf4r3M2HzY6JTHvcYGGc7dJNA3Xe"
  "WfCrYIvg0SGCP_z7Y2wICIA36VMwR3gnwNZlKkx6WGCCgsaU6IbLm4HpRBZfajuiOlasoYN4z1R"
  "lQ14Z32fdaFy8xOqLl-ZukxjWa7wv9zOSveH6JcHap1FS3R-RZ7E5WhfjxSTS0nWWZgmAjS2PkP"
  "9g4GPNsnpsrVymI39j6R6jPoc3__2EGN6qAvmp4pFKR7lQyslgNn2vYLuE0Ps5mIXVkxNiZOO3T"
  "jxgZyHaHOm1KmAZKI0EfddMATJCTt-UeLG3haqS_pYaBWcQ_xzWhoEHWU7_6ZaWrWemV8CVCg6s"
  "OB1SRI5MrkRBBSV0r8UKddLJGthZVjuTG75KK72KE9yhe86mCadvfVYe5keJ5GOC-t1EiFzBo4c"
  "4oqwkOCkkmYX_BEuZ3pOWztFp1_Br2Tl_fziw4O2vNIPCXB9yEewV6PkYPziTue3x4vRqD_mYjm"
  "1ia8fxISQnEC0vrqvrFFs9fLAHPlsvaRFnhv_XKpRwFoBdfqWTakb3k6uRz0Oh2SJ8euzFIyQNB"
  "efesMWk45DSrQjnlwlKXwZSiDKjAss0W2WwIb9F_x5LdB1Aa-CBudLVdxf62ggYaNZ57qx3YeHA"
  "jkqMGIF7Fq09D4OxM0jRsnrmXbJWKleUpJi7nHJgQGZk2ifN95gjuTNcRaGfYXMOsDoWdkrNAq0"
  "LScsPB06xEUR0DcO9vWx0zAEK7gsxxHziR7ZaYiIIkPysRR92r2NoLFPOUXf8j8ait-51jZmPKn"
  "bD6adieLy6ujSl907QsUgyGvokLs1OCsYHZr-X6vnyMjdk4G3QfmWwRepD_CMyXGvtLbTNCto7E"
  "L_M2yPZveAwYWwNlBtWK21gwIU2dgY298z7_S6jaQBc29f25sREjvN793ttYsPaeyom08qHYDnb"
  "jae3XX-2qqde6AGXlv__jO8WDZ5od6DWu2ThqV10ijVGFfGniRsSruzq0iq8zuAqTOGhmA9Dw7b"
  "rNlI95P4LpJA5pbjmNdnX7CQa2oHUuojmwlXRYuOA28PNEf-sc7ZPmMyFzedJi4EpkqzeQspEdH"
  "yNMf23iEjK6GOff7dgAaxg9vYHyprhkEml4BdmFVYwCYQy8o6KRcA0NgJb8c3tg4d3aRXWp6L-F"
  "sVhwqvq6FLOunSTNRIqhr2mOjRpU5w4mx-9GJRtk4XEcKT9YgUHGOUjGwfhQ5gBQDyZZVTddIUb"
  "MOThsSg7zr38oUCfgXeZaai3X2foKo1Bt94Q_q18dw5xNAN5e7rSwfilltHL23zbZduuhWkvp8S"
  "dag_NbO2C4IRMkzbjQBmiO9ixjXRhdqHlRRWcfR0wbQvEhD47egRVfnhKZ0W9G2-FGhyGuwJCq4"
  "CCAISEAfZ_94TqpXBImeAUzYhNr0Y48SbiwUijgIwggEKAoIBAQDRigR9nFm4mfBUh1Y3SGyOcF"
  "E-yK2NtfDiQe9l70KtkOeH4sB6MMB8g1QKPbUE8SBjPvXVJC_2DAWKjALzk4Aw-K-VmYe_Ag9CH"
  "JiS-XcfUYEGgK4jVMxadEq3LufEEREKUZnzjgQlR39dzgjFqIrC1bwfy3_99RsjPt6QpWPg36PI"
  "O4UKlmwBDTFzSOJB-4IV8Opy5Zv84BqPuyO9P5e3bXj_shRfy_XAGG2HGP_PpOCZWEfxuce0Iyu"
  "vpTPLQpTOgNw-VvUBGCWMZFoERopmqp_pQwWZ2a-EwlT_vvYY4SkuNjflBskR70xz4QzEo9665g"
  "k6I-HbHrTv29KEiAllAgMBAAEomSASgAIkKz1CSdFJVKcpO56jW0vsjKp92_cdqXBSEY3nuhzug"
  "_LFluMJx_IqATUcCOY-w6w0yKn2ezfZGE0MDIaCngEgQFI_DRoaSOBNNeirF59uYM0sK3P2eGS9"
  "G6F0l-OUXJdSO0b_LO8AbAK9LA3j7UHaajupJI1mdc4VtJfPRTsml2vIeKhDWXWaSvmeHgfF_tp"
  "-OV7oPuk6Ub26xpCp2He2rEAblCYEl25Zlz97K4DhyTOV5_xuSdSt-KbTLY9cWM5i9ncND1RzCc"
  "4qOixKarnMM5DdpZhs3B5xVj3yBAM1mVxPD2sZnqHSEN2EK7BMlHEnnyxhX0MGE36TQZR7P-I-G"
  "rUFCq8CCAESEDAxMjM0NTY3ODlBQkNERUYYspIEIo4CMIIBCgKCAQEApwA2YGXcvVRaKkC04RWU"
  "WBFPlFjd3qcfPCzgiAkpYVdnXlZ-7iePWTSaKqqdtE76p2rUyXpTwU6f4zT3PbfJEEdPKNo_zjF"
  "7_QYQ6_e-kvmv-z5o2u4aZEzzKfJznjnY9m_YsoCCcY61pPLCPs0KyrYEzZoTi1RzVCVUjL6Yem"
  "et2rNOs_qCqEpnmFZXVHHNEn_towHAaoskA5aIvpdmKrxTyYMGUVqIZRMY5Drta_FhW0zIHvTCr"
  "gheLV_4En-i_LshGDDa_kD7AcouNw7O3XaHgkYLOnePwHIHLH-dHoZb7Scp3wOXYu9E01s925xe"
  "G3s5tAttBGu7uyxfz7N6BQIDAQABKNKF2MwEEoADe9NAqNAxHpU13bMgz8LPySZJU8hY1RLwcfT"
  "UM47Xb3m-F-s2cfI7w08668f79kD45uRRzkVc8GbRIlVyzVC0WgIvtxEkYRKfgF_J7snUe2J2NN"
  "1FrkK7H3oYhcfPyYZH_SPZJr5HPoBFQTmS5A4l24U1dzQ6Z7_q-oS6uT0DiagTnzWhEg6AEnIkT"
  "sJtK3cZuKGYq3NDefZ7nslPuLXxdXl6SAEOtrk-RvCY6EBqYOuPUXgxXOEPbyM289R6aHQyPPYw"
  "qs9Pt9_E4BuMqCsbf5H5mLms9FA-wRx6mK2IaOboT4tf9_YObp3hVeL3WyxzXncETzJdE1GPGlO"
  "t_x5S_MylgJKbiWQYSdmqs3fzYExunw3wvI4tPHT_O8A_xKjyTEAvE5cBuCkfjwT716qUOzFUzF"
  "gZYLHnFiQLZekZUbUUlWY_CwU9Cv0UtxqQ6Oa835_Ug8_n1BwX6BPbmbcWe2Y19laSnDWg4JBNl"
  "F2CyP9N75jPtW9rVfjUSqKEPOwaIgwzNDkyMjM3NDcAAAA=\","
  "\"signature\": \"r-LpoZcbbr2KtoPaFnuWTVBh4Gup1k8vn0ClW2qm32A=\"}}";
}  // namespace

namespace wvcdm {

class WvCdmEngineTest : public testing::Test {
 public:
  virtual void SetUp() {
    cdm_engine_.reset(new CdmEngine());
    cdm_engine_->OpenSession(g_key_system, NULL, &session_id_);
  }

  virtual void TearDown() {
    cdm_engine_->CloseSession(session_id_);
  }

 protected:
  void GenerateKeyRequest(const std::string& key_system,
                          const std::string& key_id) {
    CdmAppParameterMap app_parameters;
    std::string server_url;
    std::string init_data = key_id;
    CdmKeySetId key_set_id;

    // TODO(rfrias): Temporary change till b/9465346 is addressed
    if (!Properties::extract_pssh_data()) {
      EXPECT_TRUE(CdmEngine::ExtractWidevinePssh(key_id, &init_data));
    }

    EXPECT_EQ(KEY_MESSAGE,
              cdm_engine_->GenerateKeyRequest(session_id_,
                                              key_set_id,
                                              init_data,
                                              kLicenseTypeStreaming,
                                              app_parameters,
                                              &key_msg_,
                                              &server_url));
  }

  void GenerateRenewalRequest(const std::string& key_system,
                              const std::string& init_data) {
    EXPECT_EQ(KEY_MESSAGE,
              cdm_engine_->GenerateRenewalRequest(session_id_,
                                                  &key_msg_,
                                                  &server_url_));
  }

  // posts a request and extracts the drm message from the response
  std::string GetKeyRequestResponse(const std::string& server_url,
                                    const std::string& client_auth,
                                    int expected_response) {
    // Use secure connection and chunk transfer coding.
    UrlRequest url_request(server_url + client_auth, g_port, true, true);
    if (!url_request.is_connected()) {
      return "";
    }

    url_request.PostRequest(key_msg_);
    std::string response;
    int resp_bytes = url_request.GetResponse(&response);
    LOGD("response:\r\n%s", response.c_str());
    LOGD("end %d bytes response dump", resp_bytes);

    // Youtube server returns 400 for invalid message while play server returns
    // 500, so just test inequity here for invalid message
    int status_code = url_request.GetStatusCode(response);
    int kHttpOk = 200;
    if (expected_response == kHttpOk) {
      EXPECT_EQ(kHttpOk, status_code);
    } else {
      EXPECT_NE(kHttpOk, status_code);
    }

    if (status_code != kHttpOk) {
      return "";
    } else {
      std::string drm_msg;
      LicenseRequest lic_request;
      lic_request.GetDrmMessage(response, drm_msg);
      LOGV("drm msg: %u bytes\r\n%s", drm_msg.size(),
      HexEncode(reinterpret_cast<const uint8_t*>(drm_msg.data()),
                drm_msg.size()).c_str());
      return drm_msg;
    }
  }

  void VerifyNewKeyResponse(const std::string& server_url,
                            const std::string& client_auth,
                            std::string& init_data){
    std::string resp = GetKeyRequestResponse(server_url,
                                             client_auth,
                                             200);
    CdmKeySetId key_set_id;
    EXPECT_EQ(cdm_engine_->AddKey(session_id_, resp, &key_set_id), KEY_ADDED);
  }

  void VerifyRenewalKeyResponse(const std::string& server_url,
                                const std::string& client_auth,
                                std::string& init_data){
    std::string resp = GetKeyRequestResponse(server_url,
                                             client_auth,
                                             200);
    EXPECT_EQ(cdm_engine_->RenewKey(session_id_, resp), wvcdm::KEY_ADDED);
  }

  scoped_ptr<CdmEngine> cdm_engine_;
  std::string key_msg_;
  std::string session_id_;
  std::string server_url_;
};

TEST(WvCdmProvisioningTest, ProvisioningTest) {
  CdmEngine cdm_engine;
  CdmProvisioningRequest prov_request;
  std::string provisioning_server_url;

  cdm_engine.GetProvisioningRequest(&prov_request, &provisioning_server_url);
  cdm_engine.HandleProvisioningResponse(kValidJsonProvisioningResponse);
}

TEST_F(WvCdmEngineTest, BaseMessageTest) {
  GenerateKeyRequest(g_key_system, g_key_id);
  GetKeyRequestResponse(g_license_server, g_client_auth, 200);
}

TEST_F(WvCdmEngineTest, WrongMessageTest) {
  std::string wrong_message = a2bs_hex(g_wrong_key_id);
  GenerateKeyRequest(g_key_system, wrong_message);
  GetKeyRequestResponse(g_license_server, g_client_auth, 500);
}

TEST_F(WvCdmEngineTest, NormalDecryption) {
  GenerateKeyRequest(g_key_system, g_key_id);
  VerifyNewKeyResponse(g_license_server, g_client_auth, g_key_id);
}

TEST_F(WvCdmEngineTest, LicenseRenewal) {
  GenerateKeyRequest(g_key_system, g_key_id);
  VerifyNewKeyResponse(g_license_server, g_client_auth, g_key_id);

  GenerateRenewalRequest(g_key_system, g_key_id);
  VerifyRenewalKeyResponse(server_url_.empty() ? g_license_server : server_url_,
                           g_client_auth,
                           g_key_id);
}

}  // namespace wvcdm

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  wvcdm::InitLogging(argc, argv);

  wvcdm::ConfigTestEnv config(wvcdm::kGooglePlayServer);
  g_client_auth.assign(config.client_auth());
  g_key_system.assign(config.key_system());
  g_wrong_key_id.assign(config.wrong_key_id());

  // The following variables are configurable through command line options.
  g_license_server.assign(config.license_server());
  g_key_id.assign(config.key_id());
  g_port.assign(config.port());
  std::string license_server(g_license_server);

  int show_usage = 0;
  static const struct option long_options[] = {
    { "use_full_path", no_argument, &g_use_full_path, 0 },
    { "keyid", required_argument, NULL, 'k' },
    { "port", required_argument, NULL, 'p' },
    { "server", required_argument, NULL, 's' },
    { "vmodule", required_argument, NULL, 0 },
    { "v", required_argument, NULL, 0 },
    { NULL, 0, NULL, '\0' }
  };

  int option_index = 0;
  int opt = 0;
  while ((opt = getopt_long(argc, argv, "k:p:s:u", long_options, &option_index)) != -1) {
    switch (opt) {
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
        g_license_server.clear();
        g_license_server.assign(optarg);
        break;
      }
      case 'u': {
        g_use_full_path = 1;
        break;
      }
      case '?': {
        show_usage = 1;
        break;
      }
    }
  }

  if (show_usage) {
    std::cout << std::endl;
    std::cout << "usage: " << argv[0] << " [options]" << std::endl << std::endl;
    std::cout << "  enclose multiple arguments in '' when using adb shell" << std::endl;
    std::cout << "  e.g. adb shell '" << argv[0] << " --server=\"url\"'" << std::endl << std::endl;

    std::cout << std::setw(30) << std::left << "    --port=<connection port>";
    std::cout << "specifies the port number, in decimal format" << std::endl;
    std::cout << std::setw(30) << std::left << " ";
    std::cout << "default: " << g_port << std::endl;

    std::cout << std::setw(30) << std::left << "    --server=<server_url>";
    std::cout << "configure the license server url, please include http[s] in the url" << std::endl;
    std::cout << std::setw(30) << std::left << " ";
    std::cout << "default: " << license_server << std::endl;

    std::cout << std::setw(30) << std::left << "    --keyid=<key_id>";
    std::cout << "configure the key id or pssh, in hex format" << std::endl;
    std::cout << std::setw(30) << std::left << "      default keyid:";
    std::cout << g_key_id << std::endl;

    std::cout << std::setw(30) << std::left << "    --use_full_path";
    std::cout << "specify server url is not a proxy server" << std::endl;
    std::cout << std::endl;
    return 0;
  }

  std::cout << std::endl;
  std::cout << "Server: " << g_license_server << std::endl;
  std::cout << "Port: " << g_port << std::endl;
  std::cout << "KeyID: " << g_key_id << std::endl << std::endl;

  g_key_id = wvcdm::a2bs_hex(g_key_id);
  config.set_license_server(g_license_server);
  config.set_port(g_port);
  config.set_key_id(g_key_id);

#if defined(CHROMIUM_BUILD)
  base::AtExitManager exit;
  MessageLoop ttr(MessageLoop::TYPE_IO);
#endif
  return RUN_ALL_TESTS();
}
