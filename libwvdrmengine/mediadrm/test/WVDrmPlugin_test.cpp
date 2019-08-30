//
// Copyright 2013 Google Inc. All Rights Reserved.
//

#include <stdio.h>
#include <string.h>
#include <string>

#include "cdm_client_property_set.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "media/stagefright/foundation/ABase.h"
#include "media/stagefright/foundation/AString.h"
#include "media/stagefright/MediaErrors.h"
#include "wv_cdm_constants.h"
#include "wv_cdm_types.h"
#include "wv_content_decryption_module.h"
#include "WVDrmPlugin.h"

using namespace android;
using namespace std;
using namespace testing;
using namespace wvcdm;
using namespace wvdrm;

class MockCDM : public WvContentDecryptionModule {
 public:
  MOCK_METHOD3(OpenSession, CdmResponseType(const CdmKeySystem&,
                                            CdmClientPropertySet*,
                                            CdmSessionId*));

  MOCK_METHOD1(CloseSession, CdmResponseType(const CdmSessionId&));

  MOCK_METHOD7(GenerateKeyRequest, CdmResponseType(const CdmSessionId&,
                                                   const CdmKeySetId&,
                                                   const CdmInitData&,
                                                   const CdmLicenseType,
                                                   CdmAppParameterMap&,
                                                   CdmKeyMessage*, string*));

  MOCK_METHOD3(AddKey, CdmResponseType(const CdmSessionId&,
                                       const CdmKeyResponse&,
                                       CdmKeySetId*));

  MOCK_METHOD1(CancelKeyRequest, CdmResponseType(const CdmSessionId&));

  MOCK_METHOD2(RestoreKey, CdmResponseType(const CdmSessionId&,
                                           const CdmKeySetId&));

  MOCK_METHOD1(QueryStatus, CdmResponseType(CdmQueryMap*));

  MOCK_METHOD2(QueryKeyStatus, CdmResponseType(const CdmSessionId&,
                                               CdmQueryMap*));

  MOCK_METHOD2(QueryKeyControlInfo, CdmResponseType(const CdmSessionId&,
                                                    CdmQueryMap*));

  MOCK_METHOD2(GetProvisioningRequest, CdmResponseType(CdmProvisioningRequest*,
                                                       std::string*));

  MOCK_METHOD1(HandleProvisioningResponse,
      CdmResponseType(CdmProvisioningResponse&));

  MOCK_METHOD1(GetSecureStops, CdmResponseType(CdmSecureStops*));

  MOCK_METHOD1(ReleaseSecureStops,
      CdmResponseType(const CdmSecureStopReleaseMessage&));

  MOCK_METHOD2(AttachEventListener, bool(const CdmSessionId&,
                                         WvCdmEventListener*));

  MOCK_METHOD2(DetachEventListener, bool(const CdmSessionId&,
                                         WvCdmEventListener*));
};

class MockCrypto : public WVGenericCryptoInterface {
 public:
  MOCK_METHOD3(selectKey, OEMCryptoResult(const OEMCrypto_SESSION,
                                          const uint8_t*, size_t));

  MOCK_METHOD6(encrypt, OEMCryptoResult(OEMCrypto_SESSION, const uint8_t*,
                                        size_t, const uint8_t*,
                                        OEMCrypto_Algorithm, uint8_t*));

  MOCK_METHOD6(decrypt, OEMCryptoResult(OEMCrypto_SESSION, const uint8_t*,
                                        size_t, const uint8_t*,
                                        OEMCrypto_Algorithm, uint8_t*));

  MOCK_METHOD6(sign, OEMCryptoResult(OEMCrypto_SESSION, const uint8_t*, size_t,
                                     OEMCrypto_Algorithm, uint8_t*, size_t*));

  MOCK_METHOD6(verify, OEMCryptoResult(OEMCrypto_SESSION, const uint8_t*,
                                       size_t, OEMCrypto_Algorithm,
                                       const uint8_t*, size_t));
};

class MockDrmPluginListener : public DrmPluginListener {
 public:
  MOCK_METHOD4(sendEvent, void(DrmPlugin::EventType, int,
                               const Vector<uint8_t>*, const Vector<uint8_t>*));
};

template <uint8_t DIGIT>
CdmResponseType setSessionIdOnMap(Unused, CdmQueryMap* map) {
  static const char oecId[] = {DIGIT + '0', '\0'};
  (*map)[QUERY_KEY_OEMCRYPTO_SESSION_ID] = oecId;
  return wvcdm::NO_ERROR;
}

class WVDrmPluginTest : public Test {
 protected:
  static const uint32_t kSessionIdSize = 16;
  uint8_t sessionIdRaw[kSessionIdSize];
  Vector<uint8_t> sessionId;
  CdmSessionId cdmSessionId;

  virtual void SetUp() {
    // Fill the session ID
    FILE* fp = fopen("/dev/urandom", "r");
    fread(sessionIdRaw, sizeof(uint8_t), kSessionIdSize, fp);
    fclose(fp);

    memcpy(sessionIdRaw, SESSION_ID_PREFIX, sizeof(SESSION_ID_PREFIX) - 1);
    sessionId.appendArray(sessionIdRaw, kSessionIdSize);
    cdmSessionId.assign(sessionId.begin(), sessionId.end());

    // Set default return values for gMock
    DefaultValue<CdmResponseType>::Set(wvcdm::NO_ERROR);
    DefaultValue<OEMCryptoResult>::Set(OEMCrypto_SUCCESS);
    DefaultValue<bool>::Set(true);
  }
};

TEST_F(WVDrmPluginTest, OpensSessions) {
  StrictMock<MockCDM> cdm;
  StrictMock<MockCrypto> crypto;
  WVDrmPlugin plugin(&cdm, &crypto);

  EXPECT_CALL(cdm, OpenSession(StrEq("com.widevine"), _, _))
      .WillOnce(DoAll(SetArgPointee<2>(cdmSessionId),
                      Return(wvcdm::NO_ERROR)));

  // Provide expected behavior when plugin requests session control info
  EXPECT_CALL(cdm, QueryKeyControlInfo(cdmSessionId, _))
      .Times(AtLeast(1))
      .WillRepeatedly(Invoke(setSessionIdOnMap<4>));

  // Let gMock know these calls will happen but we aren't interested in them.
  EXPECT_CALL(cdm, AttachEventListener(_, _))
      .Times(AtLeast(0));

  EXPECT_CALL(cdm, DetachEventListener(_, _))
      .Times(AtLeast(0));

  EXPECT_CALL(cdm, CloseSession(_))
      .Times(AtLeast(0));

  status_t res = plugin.openSession(sessionId);

  ASSERT_EQ(OK, res);
  EXPECT_THAT(sessionId, ElementsAreArray(sessionIdRaw, kSessionIdSize));
}

TEST_F(WVDrmPluginTest, ClosesSessions) {
  StrictMock<MockCDM> cdm;
  StrictMock<MockCrypto> crypto;
  WVDrmPlugin plugin(&cdm, &crypto);

  EXPECT_CALL(cdm, CloseSession(cdmSessionId))
      .Times(1);

  status_t res = plugin.closeSession(sessionId);

  ASSERT_EQ(OK, res);
}

TEST_F(WVDrmPluginTest, GeneratesKeyRequests) {
  StrictMock<MockCDM> cdm;
  StrictMock<MockCrypto> crypto;
  WVDrmPlugin plugin(&cdm, &crypto);

  static const size_t kInitDataSize = 128;
  uint8_t initDataRaw[kInitDataSize];
  static const size_t kRequestSize = 256;
  uint8_t requestRaw[kRequestSize];
  static const uint32_t kKeySetIdSize = 32;
  uint8_t keySetIdRaw[kKeySetIdSize];
  FILE* fp = fopen("/dev/urandom", "r");
  fread(initDataRaw, sizeof(uint8_t), kInitDataSize, fp);
  fread(requestRaw, sizeof(uint8_t), kRequestSize, fp);
  fread(keySetIdRaw, sizeof(uint8_t), kKeySetIdSize, fp);
  fclose(fp);

  memcpy(keySetIdRaw, KEY_SET_ID_PREFIX, sizeof(KEY_SET_ID_PREFIX) - 1);
  CdmKeySetId cdmKeySetId(reinterpret_cast<char *>(keySetIdRaw), kKeySetIdSize);
  Vector<uint8_t> keySetId;
  keySetId.appendArray(keySetIdRaw, kKeySetIdSize);

  Vector<uint8_t> initData;
  initData.appendArray(initDataRaw, kInitDataSize);

  static const uint8_t psshPrefix[] = {
    0, 0, 0, 32 + kInitDataSize,                    // Total size
    'p', 's', 's', 'h',                             // "PSSH"
    0, 0, 0, 0,                                     // Flags - must be zero
    0xED, 0xEF, 0x8B, 0xA9, 0x79, 0xD6, 0x4A, 0xCE, // Widevine UUID
    0xA3, 0xC8, 0x27, 0xDC, 0xD5, 0x1D, 0x21, 0xED,
    0, 0, 0, kInitDataSize                          // Size of initData
  };
  static const size_t kPsshPrefixSize = sizeof(psshPrefix);
  static const size_t kPsshBoxSize = kPsshPrefixSize + kInitDataSize;
  uint8_t psshBox[kPsshBoxSize];
  memcpy(psshBox, psshPrefix, kPsshPrefixSize);
  memcpy(psshBox + kPsshPrefixSize, initDataRaw, kInitDataSize);

  CdmKeyMessage cdmRequest(requestRaw, requestRaw + kRequestSize);

  KeyedVector<String8, String8> parameters;
  CdmAppParameterMap cdmParameters;

  parameters.add(String8("paddingScheme"), String8("PKCS7"));
  cdmParameters["paddingScheme"] = "PKCS7";
  parameters.add(String8("favoriteParticle"), String8("tetraquark"));
  cdmParameters["favoriteParticle"] = "tetraquark";
  parameters.add(String8("answer"), String8("42"));
  cdmParameters["answer"] = "42";

  static const char* kDefaultUrl = "http://google.com/";

  {
    InSequence calls;

    EXPECT_CALL(cdm, GenerateKeyRequest(cdmSessionId, "",
                                        ElementsAreArray(psshBox, kPsshBoxSize),
                                        kLicenseTypeOffline, cdmParameters, _,
                                        _))
        .WillOnce(DoAll(SetArgPointee<5>(cdmRequest),
                        SetArgPointee<6>(kDefaultUrl),
                        Return(wvcdm::KEY_MESSAGE)));

    EXPECT_CALL(cdm, GenerateKeyRequest(cdmSessionId, "",
                                        ElementsAreArray(psshBox, kPsshBoxSize),
                                        kLicenseTypeStreaming, cdmParameters, _,
                                        _))
        .WillOnce(DoAll(SetArgPointee<5>(cdmRequest),
                        SetArgPointee<6>(kDefaultUrl),
                        Return(wvcdm::KEY_MESSAGE)));

    EXPECT_CALL(cdm, GenerateKeyRequest("", cdmKeySetId,
                                        ElementsAreArray(psshBox, kPsshBoxSize),
                                        kLicenseTypeRelease, cdmParameters, _,
                                        _))
        .WillOnce(DoAll(SetArgPointee<5>(cdmRequest),
                        SetArgPointee<6>(kDefaultUrl),
                        Return(wvcdm::KEY_MESSAGE)));
  }

  Vector<uint8_t> request;
  String8 defaultUrl;

  status_t res = plugin.getKeyRequest(sessionId, initData,
                                      String8("video/h264"),
                                      DrmPlugin::kKeyType_Offline,
                                      parameters, request, defaultUrl);
  ASSERT_EQ(OK, res);
  EXPECT_THAT(request, ElementsAreArray(requestRaw, kRequestSize));
  EXPECT_STREQ(kDefaultUrl, defaultUrl.string());

  res = plugin.getKeyRequest(sessionId, initData, String8("video/h264"),
                             DrmPlugin::kKeyType_Streaming, parameters,
                             request, defaultUrl);
  ASSERT_EQ(OK, res);
  EXPECT_THAT(request, ElementsAreArray(requestRaw, kRequestSize));
  EXPECT_STREQ(kDefaultUrl, defaultUrl.string());

  res = plugin.getKeyRequest(keySetId, initData, String8("video/h264"),
                             DrmPlugin::kKeyType_Release, parameters,
                             request, defaultUrl);
  ASSERT_EQ(OK, res);
  EXPECT_THAT(request, ElementsAreArray(requestRaw, kRequestSize));
  EXPECT_STREQ(kDefaultUrl, defaultUrl.string());
}

TEST_F(WVDrmPluginTest, AddsKeys) {
  StrictMock<MockCDM> cdm;
  StrictMock<MockCrypto> crypto;
  WVDrmPlugin plugin(&cdm, &crypto);

  static const uint32_t kResponseSize = 256;
  uint8_t responseRaw[kResponseSize];
  static const uint32_t kKeySetIdSize = 32;
  uint8_t keySetIdRaw[kKeySetIdSize];
  FILE* fp = fopen("/dev/urandom", "r");
  fread(responseRaw, sizeof(uint8_t), kResponseSize, fp);
  fread(keySetIdRaw, sizeof(uint8_t), kKeySetIdSize, fp);
  fclose(fp);

  Vector<uint8_t> response;
  response.appendArray(responseRaw, kResponseSize);

  memcpy(keySetIdRaw, KEY_SET_ID_PREFIX, sizeof(KEY_SET_ID_PREFIX) - 1);
  CdmKeySetId cdmKeySetId(reinterpret_cast<char *>(keySetIdRaw), kKeySetIdSize);
  Vector<uint8_t> keySetId;

  Vector<uint8_t> emptyKeySetId;

  EXPECT_CALL(cdm, AddKey(cdmSessionId,
                          ElementsAreArray(responseRaw, kResponseSize), _))
      .WillOnce(DoAll(SetArgPointee<2>(cdmKeySetId),
                      Return(wvcdm::KEY_ADDED)));

  EXPECT_CALL(cdm, AddKey("", ElementsAreArray(responseRaw, kResponseSize),
                          Pointee(cdmKeySetId)))
      .Times(1);

  status_t res = plugin.provideKeyResponse(sessionId, response, keySetId);
  ASSERT_EQ(OK, res);
  ASSERT_THAT(keySetId, ElementsAreArray(keySetIdRaw, kKeySetIdSize));

  res = plugin.provideKeyResponse(keySetId, response, emptyKeySetId);
  ASSERT_EQ(OK, res);
  EXPECT_EQ(0u, emptyKeySetId.size());
}

TEST_F(WVDrmPluginTest, HandlesPrivacyCertCaseOfAddKey) {
  StrictMock<MockCDM> cdm;
  StrictMock<MockCrypto> crypto;
  WVDrmPlugin plugin(&cdm, &crypto);

  sp<StrictMock<MockDrmPluginListener> > listener =
      new StrictMock<MockDrmPluginListener>();

  const CdmClientPropertySet* propertySet = NULL;

  // Provide expected behavior in response to OpenSession and store the
  // property set
  EXPECT_CALL(cdm, OpenSession(_, _, _))
      .WillRepeatedly(DoAll(SetArgPointee<2>(cdmSessionId),
                      SaveArg<1>(&propertySet),
                      Return(wvcdm::NO_ERROR)));

  // Provide expected behavior when plugin requests session control info
  EXPECT_CALL(cdm, QueryKeyControlInfo(cdmSessionId, _))
      .WillRepeatedly(Invoke(setSessionIdOnMap<4>));

  // Let gMock know these calls will happen but we aren't interested in them.
  EXPECT_CALL(cdm, AttachEventListener(_, _))
      .Times(AtLeast(0));

  EXPECT_CALL(cdm, DetachEventListener(_, _))
      .Times(AtLeast(0));

  EXPECT_CALL(cdm, CloseSession(_))
      .Times(AtLeast(0));

  static const uint32_t kResponseSize = 256;
  uint8_t responseRaw[kResponseSize];
  FILE* fp = fopen("/dev/urandom", "r");
  fread(responseRaw, sizeof(uint8_t), kResponseSize, fp);
  fclose(fp);

  Vector<uint8_t> response;
  response.appendArray(responseRaw, kResponseSize);
  Vector<uint8_t> keySetId;

  EXPECT_CALL(*listener, sendEvent(DrmPlugin::kDrmPluginEventKeyNeeded, 0,
                                   Pointee(ElementsAreArray(sessionIdRaw,
                                                            kSessionIdSize)),
                                   NULL))
      .Times(1);

  EXPECT_CALL(cdm, AddKey(_, _, _))
      .WillRepeatedly(Return(wvcdm::NEED_KEY));

  plugin.openSession(sessionId);
  ASSERT_THAT(propertySet, NotNull());

  status_t res = plugin.setListener(listener);
  ASSERT_EQ(OK, res);

  res = plugin.setPropertyString(String8("privacyMode"), String8("enable"));
  ASSERT_EQ(OK, res);
  EXPECT_TRUE(propertySet->use_privacy_mode());

  res = plugin.provideKeyResponse(sessionId, response, keySetId);
  ASSERT_EQ(OK, res);
}

TEST_F(WVDrmPluginTest, CancelsKeyRequests) {
  StrictMock<MockCDM> cdm;
  StrictMock<MockCrypto> crypto;
  WVDrmPlugin plugin(&cdm, &crypto);

  EXPECT_CALL(cdm, CancelKeyRequest(cdmSessionId))
      .Times(1);

  status_t res = plugin.removeKeys(sessionId);
  ASSERT_EQ(OK, res);
}

TEST_F(WVDrmPluginTest, RestoresKeys) {
  StrictMock<MockCDM> cdm;
  StrictMock<MockCrypto> crypto;
  WVDrmPlugin plugin(&cdm, &crypto);

  static const size_t kKeySetIdSize = 32;
  uint8_t keySetIdRaw[kKeySetIdSize];
  FILE* fp = fopen("/dev/urandom", "r");
  fread(keySetIdRaw, sizeof(uint8_t), kKeySetIdSize, fp);
  fclose(fp);

  Vector<uint8_t> keySetId;
  keySetId.appendArray(keySetIdRaw, kKeySetIdSize);

  EXPECT_CALL(cdm, RestoreKey(cdmSessionId,
                              ElementsAreArray(keySetIdRaw, kKeySetIdSize)))
      .Times(1);

  status_t res = plugin.restoreKeys(sessionId, keySetId);
  ASSERT_EQ(OK, res);
}

TEST_F(WVDrmPluginTest, QueriesKeyStatus) {
  StrictMock<MockCDM> cdm;
  StrictMock<MockCrypto> crypto;
  WVDrmPlugin plugin(&cdm, &crypto);

  KeyedVector<String8, String8> expectedLicenseStatus;
  CdmQueryMap cdmLicenseStatus;

  expectedLicenseStatus.add(String8("areTheKeysAllRight"), String8("yes"));
  cdmLicenseStatus["areTheKeysAllRight"] = "yes";
  expectedLicenseStatus.add(String8("isGMockAwesome"), String8("ohhhhhhYeah"));
  cdmLicenseStatus["isGMockAwesome"] = "ohhhhhhYeah";
  expectedLicenseStatus.add(String8("answer"), String8("42"));
  cdmLicenseStatus["answer"] = "42";

  EXPECT_CALL(cdm, QueryKeyStatus(cdmSessionId, _))
      .WillOnce(DoAll(SetArgPointee<1>(cdmLicenseStatus),
                      Return(wvcdm::NO_ERROR)));

  KeyedVector<String8, String8> licenseStatus;

  status_t res = plugin.queryKeyStatus(sessionId, licenseStatus);

  ASSERT_EQ(OK, res);

  ASSERT_EQ(expectedLicenseStatus.size(), licenseStatus.size());
  for (size_t i = 0; i < expectedLicenseStatus.size(); ++i) {
    const String8& key = expectedLicenseStatus.keyAt(i);
    EXPECT_NE(android::NAME_NOT_FOUND, licenseStatus.indexOfKey(key));
    EXPECT_EQ(expectedLicenseStatus.valueFor(key), licenseStatus.valueFor(key));
  }
}

TEST_F(WVDrmPluginTest, GetsProvisioningRequests) {
  StrictMock<MockCDM> cdm;
  StrictMock<MockCrypto> crypto;
  WVDrmPlugin plugin(&cdm, &crypto);

  static const uint32_t kRequestSize = 256;
  uint8_t requestRaw[kRequestSize];
  FILE* fp = fopen("/dev/urandom", "r");
  fread(requestRaw, sizeof(uint8_t), kRequestSize, fp);
  fclose(fp);

  CdmProvisioningRequest cdmRequest(requestRaw, requestRaw + kRequestSize);

  static const char* kDefaultUrl = "http://google.com/";

  EXPECT_CALL(cdm, GetProvisioningRequest(_, _))
      .WillOnce(DoAll(SetArgPointee<0>(cdmRequest),
                      SetArgPointee<1>(kDefaultUrl),
                      Return(wvcdm::NO_ERROR)));

  Vector<uint8_t> request;
  String8 defaultUrl;

  status_t res = plugin.getProvisionRequest(request, defaultUrl);

  ASSERT_EQ(OK, res);
  EXPECT_THAT(request, ElementsAreArray(requestRaw, kRequestSize));
  EXPECT_STREQ(kDefaultUrl, defaultUrl.string());
}

TEST_F(WVDrmPluginTest, HandlesProvisioningResponses) {
  StrictMock<MockCDM> cdm;
  StrictMock<MockCrypto> crypto;
  WVDrmPlugin plugin(&cdm, &crypto);

  static const uint32_t kResponseSize = 512;
  uint8_t responseRaw[kResponseSize];
  FILE* fp = fopen("/dev/urandom", "r");
  fread(responseRaw, sizeof(uint8_t), kResponseSize, fp);
  fclose(fp);

  Vector<uint8_t> response;
  response.appendArray(responseRaw, kResponseSize);

  EXPECT_CALL(cdm, HandleProvisioningResponse(ElementsAreArray(responseRaw,
                                                               kResponseSize)))
      .Times(1);

  status_t res = plugin.provideProvisionResponse(response);

  ASSERT_EQ(OK, res);
}

TEST_F(WVDrmPluginTest, GetsSecureStops) {
  StrictMock<MockCDM> cdm;
  StrictMock<MockCrypto> crypto;
  WVDrmPlugin plugin(&cdm, &crypto);

  static const uint32_t kStopSize = 53;
  static const uint32_t kStopCount = 7;
  uint8_t stopsRaw[kStopCount][kStopSize];
  FILE* fp = fopen("/dev/urandom", "r");
  for (uint32_t i = 0; i < kStopCount; ++i) {
    fread(stopsRaw[i], sizeof(uint8_t), kStopSize, fp);
  }
  fclose(fp);

  CdmSecureStops cdmStops;
  for (uint32_t i = 0; i < kStopCount; ++i) {
    cdmStops.push_back(string(stopsRaw[i], stopsRaw[i] + kStopSize));
  }

  EXPECT_CALL(cdm, GetSecureStops(_))
      .WillOnce(DoAll(SetArgPointee<0>(cdmStops),
                      Return(wvcdm::NO_ERROR)));

  List<Vector<uint8_t> > stops;

  status_t res = plugin.getSecureStops(stops);

  ASSERT_EQ(OK, res);

  List<Vector<uint8_t> >::iterator iter = stops.begin();
  uint32_t rawIter = 0;
  while (rawIter < kStopCount && iter != stops.end()) {
    EXPECT_THAT(*iter, ElementsAreArray(stopsRaw[rawIter], kStopSize));

    ++iter;
    ++rawIter;
  }
  // Assert that both lists are the same length
  EXPECT_EQ(kStopCount, rawIter);
  EXPECT_EQ(stops.end(), iter);
}

TEST_F(WVDrmPluginTest, ReleasesSecureStops) {
  StrictMock<MockCDM> cdm;
  StrictMock<MockCrypto> crypto;
  WVDrmPlugin plugin(&cdm, &crypto);

  static const uint32_t kMessageSize = 128;
  uint8_t messageRaw[kMessageSize];
  FILE* fp = fopen("/dev/urandom", "r");
  fread(messageRaw, sizeof(uint8_t), kMessageSize, fp);
  fclose(fp);

  Vector<uint8_t> message;
  message.appendArray(messageRaw, kMessageSize);

  EXPECT_CALL(cdm, ReleaseSecureStops(ElementsAreArray(messageRaw,
                                                       kMessageSize)))
      .Times(1);

  status_t res = plugin.releaseSecureStops(message);

  ASSERT_EQ(OK, res);
}

TEST_F(WVDrmPluginTest, ReturnsExpectedPropertyValues) {
  StrictMock<MockCDM> cdm;
  StrictMock<MockCrypto> crypto;
  WVDrmPlugin plugin(&cdm, &crypto);

  CdmQueryMap l1Map;
  l1Map[QUERY_KEY_SECURITY_LEVEL] = QUERY_VALUE_SECURITY_LEVEL_L1;

  CdmQueryMap l3Map;
  l3Map[QUERY_KEY_SECURITY_LEVEL] = QUERY_VALUE_SECURITY_LEVEL_L3;

  static const string uniqueId = "The Universe";
  CdmQueryMap deviceIDMap;
  deviceIDMap[QUERY_KEY_DEVICE_ID] = uniqueId;

  static const string systemId = "42";
  CdmQueryMap systemIDMap;
  systemIDMap[QUERY_KEY_SYSTEM_ID] = systemId;

  static const string provisioningId("Life\0&Everything", 16);
  CdmQueryMap provisioningIDMap;
  provisioningIDMap[QUERY_KEY_PROVISIONING_ID] = provisioningId;

  EXPECT_CALL(cdm, QueryStatus(_))
    .WillOnce(DoAll(SetArgPointee<0>(l1Map),
                    Return(wvcdm::NO_ERROR)))
    .WillOnce(DoAll(SetArgPointee<0>(l3Map),
                    Return(wvcdm::NO_ERROR)))
    .WillOnce(DoAll(SetArgPointee<0>(deviceIDMap),
                    Return(wvcdm::NO_ERROR)))
    .WillOnce(DoAll(SetArgPointee<0>(systemIDMap),
                    Return(wvcdm::NO_ERROR)))
    .WillOnce(DoAll(SetArgPointee<0>(provisioningIDMap),
                    Return(wvcdm::NO_ERROR)));

  String8 stringResult;
  Vector<uint8_t> vectorResult;

  status_t res = plugin.getPropertyString(String8("vendor"), stringResult);
  ASSERT_EQ(OK, res);
  EXPECT_STREQ("Google", stringResult.string());

  res = plugin.getPropertyString(String8("version"), stringResult);
  ASSERT_EQ(OK, res);
  EXPECT_STREQ("1.0", stringResult.string());

  res = plugin.getPropertyString(String8("description"), stringResult);
  ASSERT_EQ(OK, res);
  EXPECT_STREQ("Widevine CDM", stringResult.string());

  res = plugin.getPropertyString(String8("algorithms"), stringResult);
  ASSERT_EQ(OK, res);
  EXPECT_STREQ("AES/CBC/NoPadding,HmacSHA256", stringResult.string());

  res = plugin.getPropertyString(String8("securityLevel"), stringResult);
  ASSERT_EQ(OK, res);
  EXPECT_STREQ(QUERY_VALUE_SECURITY_LEVEL_L1.c_str(), stringResult.string());

  res = plugin.getPropertyString(String8("securityLevel"), stringResult);
  ASSERT_EQ(OK, res);
  EXPECT_STREQ(QUERY_VALUE_SECURITY_LEVEL_L3.c_str(), stringResult.string());

  res = plugin.getPropertyByteArray(String8("deviceUniqueId"), vectorResult);
  ASSERT_EQ(OK, res);
  EXPECT_THAT(vectorResult, ElementsAreArray(uniqueId.data(), uniqueId.size()));

  res = plugin.getPropertyString(String8("systemId"), stringResult);
  ASSERT_EQ(OK, res);
  EXPECT_STREQ(systemId.c_str(), stringResult.string());

  res = plugin.getPropertyByteArray(String8("provisioningUniqueId"), vectorResult);
  ASSERT_EQ(OK, res);
  EXPECT_THAT(vectorResult, ElementsAreArray(provisioningId.data(),
                                             provisioningId.size()));
}

TEST_F(WVDrmPluginTest, DoesNotGetUnknownProperties) {
  StrictMock<MockCDM> cdm;
  StrictMock<MockCrypto> crypto;
  WVDrmPlugin plugin(&cdm, &crypto);

  String8 stringResult;
  Vector<uint8_t> vectorResult;

  status_t res = plugin.getPropertyString(String8("unknownProperty"),
                                          stringResult);
  ASSERT_NE(OK, res);
  EXPECT_TRUE(stringResult.isEmpty());

  res = plugin.getPropertyByteArray(String8("unknownProperty"),
                                             vectorResult);
  ASSERT_NE(OK, res);
  EXPECT_TRUE(vectorResult.isEmpty());
}

TEST_F(WVDrmPluginTest, DoesNotSetProperties) {
  StrictMock<MockCDM> cdm;
  StrictMock<MockCrypto> crypto;
  WVDrmPlugin plugin(&cdm, &crypto);

  static const uint32_t kValueSize = 32;
  uint8_t valueRaw[kValueSize];
  FILE* fp = fopen("/dev/urandom", "r");
  fread(valueRaw, sizeof(uint8_t), kValueSize, fp);
  fclose(fp);

  Vector<uint8_t> value;
  value.appendArray(valueRaw, kValueSize);

  status_t res = plugin.setPropertyString(String8("property"),
                                          String8("ignored"));
  ASSERT_NE(OK, res);

  res = plugin.setPropertyByteArray(String8("property"), value);
  ASSERT_NE(OK, res);
}

TEST_F(WVDrmPluginTest, FailsGenericMethodsWithoutAnAlgorithmSet) {
  StrictMock<MockCDM> cdm;
  StrictMock<MockCrypto> crypto;
  WVDrmPlugin plugin(&cdm, &crypto);

  Vector<uint8_t> keyId;
  Vector<uint8_t> input;
  Vector<uint8_t> iv;
  Vector<uint8_t> output;
  bool match;

  // Provide expected behavior to support session creation
  EXPECT_CALL(cdm, OpenSession(StrEq("com.widevine"), _, _))
      .Times(AtLeast(1))
      .WillRepeatedly(DoAll(SetArgPointee<2>(cdmSessionId),
                            Return(wvcdm::NO_ERROR)));

  EXPECT_CALL(cdm, QueryKeyControlInfo(cdmSessionId, _))
      .Times(AtLeast(1))
      .WillRepeatedly(Invoke(setSessionIdOnMap<4>));

  // Let gMock know these calls will happen but we aren't interested in them.
  EXPECT_CALL(cdm, AttachEventListener(_, _))
      .Times(AtLeast(0));

  EXPECT_CALL(cdm, DetachEventListener(_, _))
      .Times(AtLeast(0));

  EXPECT_CALL(cdm, CloseSession(_))
      .Times(AtLeast(0));

  status_t res = plugin.openSession(sessionId);
  ASSERT_EQ(OK, res);

  // Note that we do not set the algorithms.  This should cause these methods
  // to fail.

  res = plugin.encrypt(sessionId, keyId, input, iv, output);
  EXPECT_EQ(NO_INIT, res);

  res = plugin.decrypt(sessionId, keyId, input, iv, output);
  EXPECT_EQ(NO_INIT, res);

  res = plugin.sign(sessionId, keyId, input, output);
  EXPECT_EQ(NO_INIT, res);

  res = plugin.verify(sessionId, keyId, input, output, match);
  EXPECT_EQ(NO_INIT, res);
}

MATCHER_P(IsIV, iv, "") {
  for (size_t i = 0; i < KEY_IV_SIZE; ++i) {
    if (iv[i] != arg[i]) {
      return false;
    }
  }

  return true;
}

TEST_F(WVDrmPluginTest, CallsGenericEncrypt) {
  StrictMock<MockCDM> cdm;
  StrictMock<MockCrypto> crypto;
  WVDrmPlugin plugin(&cdm, &crypto);

  static const size_t kDataSize = 256;
  uint8_t keyIdRaw[KEY_ID_SIZE];
  uint8_t inputRaw[kDataSize];
  uint8_t ivRaw[KEY_IV_SIZE];

  FILE* fp = fopen("/dev/urandom", "r");
  fread(keyIdRaw, sizeof(uint8_t), KEY_ID_SIZE, fp);
  fread(inputRaw, sizeof(uint8_t), kDataSize, fp);
  fread(ivRaw, sizeof(uint8_t), KEY_IV_SIZE, fp);
  fclose(fp);

  Vector<uint8_t> keyId;
  keyId.appendArray(keyIdRaw, KEY_ID_SIZE);
  Vector<uint8_t> input;
  input.appendArray(inputRaw, kDataSize);
  Vector<uint8_t> iv;
  iv.appendArray(ivRaw, KEY_IV_SIZE);
  Vector<uint8_t> output;

  {
    InSequence calls;

    EXPECT_CALL(crypto, selectKey(4, _, KEY_ID_SIZE))
        .With(Args<1, 2>(ElementsAreArray(keyIdRaw, KEY_ID_SIZE)))
        .Times(1);

    EXPECT_CALL(crypto, encrypt(4, _, kDataSize, IsIV(ivRaw),
                                OEMCrypto_AES_CBC_128_NO_PADDING, _))
        .With(Args<1, 2>(ElementsAreArray(inputRaw, kDataSize)))
        .Times(1);
  }

  // Provide expected behavior to support session creation
  EXPECT_CALL(cdm, OpenSession(StrEq("com.widevine"), _, _))
      .Times(AtLeast(1))
      .WillRepeatedly(DoAll(SetArgPointee<2>(cdmSessionId),
                            Return(wvcdm::NO_ERROR)));

  EXPECT_CALL(cdm, QueryKeyControlInfo(cdmSessionId, _))
      .Times(AtLeast(1))
      .WillRepeatedly(Invoke(setSessionIdOnMap<4>));

  // Let gMock know these calls will happen but we aren't interested in them.
  EXPECT_CALL(cdm, AttachEventListener(_, _))
      .Times(AtLeast(0));

  EXPECT_CALL(cdm, DetachEventListener(_, _))
      .Times(AtLeast(0));

  EXPECT_CALL(cdm, CloseSession(_))
      .Times(AtLeast(0));

  status_t res = plugin.openSession(sessionId);
  ASSERT_EQ(OK, res);

  res = plugin.setCipherAlgorithm(sessionId, String8("AES/CBC/NoPadding"));
  ASSERT_EQ(OK, res);

  res = plugin.encrypt(sessionId, keyId, input, iv, output);
  ASSERT_EQ(OK, res);
}

TEST_F(WVDrmPluginTest, CallsGenericDecrypt) {
  StrictMock<MockCDM> cdm;
  StrictMock<MockCrypto> crypto;
  WVDrmPlugin plugin(&cdm, &crypto);

  static const size_t kDataSize = 256;
  uint8_t keyIdRaw[KEY_ID_SIZE];
  uint8_t inputRaw[kDataSize];
  uint8_t ivRaw[KEY_IV_SIZE];

  FILE* fp = fopen("/dev/urandom", "r");
  fread(keyIdRaw, sizeof(uint8_t), KEY_ID_SIZE, fp);
  fread(inputRaw, sizeof(uint8_t), kDataSize, fp);
  fread(ivRaw, sizeof(uint8_t), KEY_IV_SIZE, fp);
  fclose(fp);

  Vector<uint8_t> keyId;
  keyId.appendArray(keyIdRaw, KEY_ID_SIZE);
  Vector<uint8_t> input;
  input.appendArray(inputRaw, kDataSize);
  Vector<uint8_t> iv;
  iv.appendArray(ivRaw, KEY_IV_SIZE);
  Vector<uint8_t> output;

  {
    InSequence calls;

    EXPECT_CALL(crypto, selectKey(4, _, KEY_ID_SIZE))
        .With(Args<1, 2>(ElementsAreArray(keyIdRaw, KEY_ID_SIZE)))
        .Times(1);

    EXPECT_CALL(crypto, decrypt(4, _, kDataSize, IsIV(ivRaw),
                                OEMCrypto_AES_CBC_128_NO_PADDING, _))
        .With(Args<1, 2>(ElementsAreArray(inputRaw, kDataSize)))
        .Times(1);
  }

  // Provide expected behavior to support session creation
  EXPECT_CALL(cdm, OpenSession(StrEq("com.widevine"), _, _))
      .Times(AtLeast(1))
      .WillRepeatedly(DoAll(SetArgPointee<2>(cdmSessionId),
                            Return(wvcdm::NO_ERROR)));

  EXPECT_CALL(cdm, QueryKeyControlInfo(cdmSessionId, _))
      .Times(AtLeast(1))
      .WillRepeatedly(Invoke(setSessionIdOnMap<4>));

  // Let gMock know these calls will happen but we aren't interested in them.
  EXPECT_CALL(cdm, AttachEventListener(_, _))
      .Times(AtLeast(0));

  EXPECT_CALL(cdm, DetachEventListener(_, _))
      .Times(AtLeast(0));

  EXPECT_CALL(cdm, CloseSession(_))
      .Times(AtLeast(0));

  status_t res = plugin.openSession(sessionId);
  ASSERT_EQ(OK, res);

  res = plugin.setCipherAlgorithm(sessionId, String8("AES/CBC/NoPadding"));
  ASSERT_EQ(OK, res);

  res = plugin.decrypt(sessionId, keyId, input, iv, output);
  ASSERT_EQ(OK, res);
}

TEST_F(WVDrmPluginTest, CallsGenericSign) {
  StrictMock<MockCDM> cdm;
  StrictMock<MockCrypto> crypto;
  WVDrmPlugin plugin(&cdm, &crypto);

  static const size_t kDataSize = 256;
  uint8_t keyIdRaw[KEY_ID_SIZE];
  uint8_t messageRaw[kDataSize];

  FILE* fp = fopen("/dev/urandom", "r");
  fread(keyIdRaw, sizeof(uint8_t), KEY_ID_SIZE, fp);
  fread(messageRaw, sizeof(uint8_t), kDataSize, fp);
  fclose(fp);

  Vector<uint8_t> keyId;
  keyId.appendArray(keyIdRaw, KEY_ID_SIZE);
  Vector<uint8_t> message;
  message.appendArray(messageRaw, kDataSize);
  Vector<uint8_t> signature;

  {
    InSequence calls;

    EXPECT_CALL(crypto, selectKey(4, _, KEY_ID_SIZE))
        .With(Args<1, 2>(ElementsAreArray(keyIdRaw, KEY_ID_SIZE)))
        .Times(1);

    EXPECT_CALL(crypto, sign(4, _, kDataSize, OEMCrypto_HMAC_SHA256, _,
                             Pointee(0)))
        .With(Args<1, 2>(ElementsAreArray(messageRaw, kDataSize)))
        .WillOnce(DoAll(SetArgPointee<5>(64),
                        Return(OEMCrypto_ERROR_SHORT_BUFFER)));

    EXPECT_CALL(crypto, sign(4, _, kDataSize, OEMCrypto_HMAC_SHA256, _,
                             Pointee(64)))
        .With(Args<1, 2>(ElementsAreArray(messageRaw, kDataSize)))
        .Times(1);
  }

  // Provide expected behavior to support session creation
  EXPECT_CALL(cdm, OpenSession(StrEq("com.widevine"), _, _))
      .Times(AtLeast(1))
      .WillRepeatedly(DoAll(SetArgPointee<2>(cdmSessionId),
                            Return(wvcdm::NO_ERROR)));

  EXPECT_CALL(cdm, QueryKeyControlInfo(cdmSessionId, _))
      .Times(AtLeast(1))
      .WillRepeatedly(Invoke(setSessionIdOnMap<4>));

  // Let gMock know these calls will happen but we aren't interested in them.
  EXPECT_CALL(cdm, AttachEventListener(_, _))
      .Times(AtLeast(0));

  EXPECT_CALL(cdm, DetachEventListener(_, _))
      .Times(AtLeast(0));

  EXPECT_CALL(cdm, CloseSession(_))
      .Times(AtLeast(0));

  status_t res = plugin.openSession(sessionId);
  ASSERT_EQ(OK, res);

  res = plugin.setMacAlgorithm(sessionId, String8("HmacSHA256"));
  ASSERT_EQ(OK, res);

  res = plugin.sign(sessionId, keyId, message, signature);
  ASSERT_EQ(OK, res);
}

TEST_F(WVDrmPluginTest, CallsGenericVerify) {
  StrictMock<MockCDM> cdm;
  StrictMock<MockCrypto> crypto;
  WVDrmPlugin plugin(&cdm, &crypto);

  static const size_t kDataSize = 256;
  static const size_t kSignatureSize = 16;
  uint8_t keyIdRaw[KEY_ID_SIZE];
  uint8_t messageRaw[kDataSize];
  uint8_t signatureRaw[kSignatureSize];

  FILE* fp = fopen("/dev/urandom", "r");
  fread(keyIdRaw, sizeof(uint8_t), KEY_ID_SIZE, fp);
  fread(messageRaw, sizeof(uint8_t), kDataSize, fp);
  fread(signatureRaw, sizeof(uint8_t), kSignatureSize, fp);
  fclose(fp);

  Vector<uint8_t> keyId;
  keyId.appendArray(keyIdRaw, KEY_ID_SIZE);
  Vector<uint8_t> message;
  message.appendArray(messageRaw, kDataSize);
  Vector<uint8_t> signature;
  signature.appendArray(signatureRaw, kSignatureSize);
  bool match;

  {
    InSequence calls;

    EXPECT_CALL(crypto, selectKey(4, _, KEY_ID_SIZE))
        .With(Args<1, 2>(ElementsAreArray(keyIdRaw, KEY_ID_SIZE)))
        .Times(1);

    EXPECT_CALL(crypto, verify(4, _, kDataSize, OEMCrypto_HMAC_SHA256, _,
                               kSignatureSize))
        .With(AllOf(Args<1, 2>(ElementsAreArray(messageRaw, kDataSize)),
                    Args<4, 5>(ElementsAreArray(signatureRaw, kSignatureSize))))
        .WillOnce(Return(OEMCrypto_SUCCESS));

    EXPECT_CALL(crypto, selectKey(4, _, KEY_ID_SIZE))
        .With(Args<1, 2>(ElementsAreArray(keyIdRaw, KEY_ID_SIZE)))
        .Times(1);

    EXPECT_CALL(crypto, verify(4, _, kDataSize, OEMCrypto_HMAC_SHA256, _,
                               kSignatureSize))
        .With(AllOf(Args<1, 2>(ElementsAreArray(messageRaw, kDataSize)),
                    Args<4, 5>(ElementsAreArray(signatureRaw, kSignatureSize))))
        .WillOnce(Return(OEMCrypto_ERROR_SIGNATURE_FAILURE));
  }

  // Provide expected behavior to support session creation
  EXPECT_CALL(cdm, OpenSession(StrEq("com.widevine"), _, _))
      .Times(AtLeast(1))
      .WillRepeatedly(DoAll(SetArgPointee<2>(cdmSessionId),
                            Return(wvcdm::NO_ERROR)));

  EXPECT_CALL(cdm, QueryKeyControlInfo(cdmSessionId, _))
      .Times(AtLeast(1))
      .WillRepeatedly(Invoke(setSessionIdOnMap<4>));

  // Let gMock know these calls will happen but we aren't interested in them.
  EXPECT_CALL(cdm, AttachEventListener(_, _))
      .Times(AtLeast(0));

  EXPECT_CALL(cdm, DetachEventListener(_, _))
      .Times(AtLeast(0));

  EXPECT_CALL(cdm, CloseSession(_))
      .Times(AtLeast(0));

  status_t res = plugin.openSession(sessionId);
  ASSERT_EQ(OK, res);

  res = plugin.setMacAlgorithm(sessionId, String8("HmacSHA256"));
  ASSERT_EQ(OK, res);

  res = plugin.verify(sessionId, keyId, message, signature, match);
  ASSERT_EQ(OK, res);
  EXPECT_TRUE(match);

  res = plugin.verify(sessionId, keyId, message, signature, match);
  ASSERT_EQ(OK, res);
  EXPECT_FALSE(match);
}

TEST_F(WVDrmPluginTest, RegistersForEvents) {
  StrictMock<MockCDM> cdm;
  StrictMock<MockCrypto> crypto;
  WVDrmPlugin plugin(&cdm, &crypto);

  EXPECT_CALL(cdm, AttachEventListener(cdmSessionId, &plugin))
      .Times(1);

  // Provide expected behavior to support session creation
  EXPECT_CALL(cdm, OpenSession(StrEq("com.widevine"), _, _))
      .Times(AtLeast(1))
      .WillRepeatedly(DoAll(SetArgPointee<2>(cdmSessionId),
                            Return(wvcdm::NO_ERROR)));

  EXPECT_CALL(cdm, QueryKeyControlInfo(cdmSessionId, _))
      .Times(AtLeast(1))
      .WillRepeatedly(Invoke(setSessionIdOnMap<4>));

  // Let gMock know this call will happen but we aren't interested in it.
  EXPECT_CALL(cdm, DetachEventListener(_, _))
      .Times(AtLeast(0));

  EXPECT_CALL(cdm, CloseSession(_))
      .Times(AtLeast(0));

  status_t res = plugin.openSession(sessionId);
  ASSERT_EQ(OK, res);
}

TEST_F(WVDrmPluginTest, UnregistersForAllEventsOnDestruction) {
  StrictMock<MockCDM> cdm;
  StrictMock<MockCrypto> crypto;

  {
    WVDrmPlugin plugin(&cdm, &crypto);

    uint8_t sessionIdRaw1[kSessionIdSize];
    uint8_t sessionIdRaw2[kSessionIdSize];
    FILE* fp = fopen("/dev/urandom", "r");
    fread(sessionIdRaw1, sizeof(uint8_t), kSessionIdSize, fp);
    fread(sessionIdRaw2, sizeof(uint8_t), kSessionIdSize, fp);
    fclose(fp);

    CdmSessionId cdmSessionId1(sessionIdRaw1, sessionIdRaw1 + kSessionIdSize);
    CdmSessionId cdmSessionId2(sessionIdRaw2, sessionIdRaw2 + kSessionIdSize);

    EXPECT_CALL(cdm, OpenSession(StrEq("com.widevine"), _, _))
        .WillOnce(DoAll(SetArgPointee<2>(cdmSessionId1),
                        Return(wvcdm::NO_ERROR)))
        .WillOnce(DoAll(SetArgPointee<2>(cdmSessionId2),
                        Return(wvcdm::NO_ERROR)));

    EXPECT_CALL(cdm, QueryKeyControlInfo(cdmSessionId1, _))
        .WillOnce(Invoke(setSessionIdOnMap<4>));

    EXPECT_CALL(cdm, QueryKeyControlInfo(cdmSessionId2, _))
        .WillOnce(Invoke(setSessionIdOnMap<5>));

    EXPECT_CALL(cdm, DetachEventListener(cdmSessionId1, &plugin))
        .Times(1);

    EXPECT_CALL(cdm, DetachEventListener(cdmSessionId2, &plugin))
        .Times(1);

    // Let gMock know these calls will happen but we aren't interested in them.
    EXPECT_CALL(cdm, AttachEventListener(_, _))
        .Times(AtLeast(0));

    EXPECT_CALL(cdm, CloseSession(_))
        .Times(AtLeast(0));

    status_t res = plugin.openSession(sessionId);
    ASSERT_EQ(OK, res);

    res = plugin.openSession(sessionId);
    ASSERT_EQ(OK, res);
  }
}

TEST_F(WVDrmPluginTest, MarshalsEvents) {
  StrictMock<MockCDM> cdm;
  StrictMock<MockCrypto> crypto;
  WVDrmPlugin plugin(&cdm, &crypto);

  sp<StrictMock<MockDrmPluginListener> > listener =
      new StrictMock<MockDrmPluginListener>();

  {
    InSequence calls;

    EXPECT_CALL(*listener, sendEvent(DrmPlugin::kDrmPluginEventKeyExpired, 0,
                                     Pointee(ElementsAreArray(sessionIdRaw,
                                                              kSessionIdSize)),
                                     NULL))
        .Times(1);

    EXPECT_CALL(*listener, sendEvent(DrmPlugin::kDrmPluginEventKeyNeeded, 0,
                                     Pointee(ElementsAreArray(sessionIdRaw,
                                                              kSessionIdSize)),
                                     NULL))
        .Times(1);
  }

  status_t res = plugin.setListener(listener);
  ASSERT_EQ(OK, res);

  plugin.onEvent(cdmSessionId, LICENSE_EXPIRED_EVENT);
  plugin.onEvent(cdmSessionId, LICENSE_RENEWAL_NEEDED_EVENT);
}

TEST_F(WVDrmPluginTest, GeneratesProvisioningNeededEvent) {
  StrictMock<MockCDM> cdm;
  StrictMock<MockCrypto> crypto;
  WVDrmPlugin plugin(&cdm, &crypto);

  sp<StrictMock<MockDrmPluginListener> > listener =
      new StrictMock<MockDrmPluginListener>();

  EXPECT_CALL(*listener, sendEvent(DrmPlugin::kDrmPluginEventProvisionRequired, 0,
                                   Pointee(ElementsAreArray(sessionIdRaw,
                                                            kSessionIdSize)),
                                   NULL))
      .Times(1);

  EXPECT_CALL(cdm, OpenSession(StrEq("com.widevine"), _, _))
      .Times(AtLeast(1))
      .WillRepeatedly(DoAll(SetArgPointee<2>(cdmSessionId),
                            Return(wvcdm::NEED_PROVISIONING)));

  // Let gMock know these calls will happen but we aren't interested in them.
  EXPECT_CALL(cdm, AttachEventListener(_, _))
      .Times(AtLeast(0));

  EXPECT_CALL(cdm, DetachEventListener(_, _))
      .Times(AtLeast(0));

  EXPECT_CALL(cdm, CloseSession(_))
      .Times(AtLeast(0));

  status_t res = plugin.setListener(listener);
  ASSERT_EQ(OK, res);

  res = plugin.openSession(sessionId);
  ASSERT_EQ(ERROR_DRM_NOT_PROVISIONED, res);
}

TEST_F(WVDrmPluginTest, ProvidesExpectedDefaultPropertiesToCdm) {
  StrictMock<MockCDM> cdm;
  StrictMock<MockCrypto> crypto;
  WVDrmPlugin plugin(&cdm, &crypto);

  const CdmClientPropertySet* propertySet = NULL;

  // Provide expected mock behavior
  {
    // Provide expected behavior in response to OpenSession and store the
    // property set
    EXPECT_CALL(cdm, OpenSession(_, _, _))
        .WillRepeatedly(DoAll(SetArgPointee<2>(cdmSessionId),
                        SaveArg<1>(&propertySet),
                        Return(wvcdm::NO_ERROR)));

    // Provide expected behavior when plugin requests session control info
    EXPECT_CALL(cdm, QueryKeyControlInfo(cdmSessionId, _))
        .WillRepeatedly(Invoke(setSessionIdOnMap<4>));

    // Let gMock know these calls will happen but we aren't interested in them.
    EXPECT_CALL(cdm, AttachEventListener(_, _))
        .Times(AtLeast(0));

    EXPECT_CALL(cdm, DetachEventListener(_, _))
        .Times(AtLeast(0));

    EXPECT_CALL(cdm, CloseSession(_))
        .Times(AtLeast(0));
  }

  plugin.openSession(sessionId);

  ASSERT_THAT(propertySet, NotNull());
  EXPECT_STREQ("", propertySet->security_level().c_str());
  EXPECT_FALSE(propertySet->use_privacy_mode());
  EXPECT_EQ(0u, propertySet->service_certificate().size());
  EXPECT_FALSE(propertySet->is_session_sharing_enabled());
  EXPECT_EQ(0u, propertySet->session_sharing_id());
}

TEST_F(WVDrmPluginTest, CanSetSecurityLevel) {
  StrictMock<MockCDM> cdm;
  StrictMock<MockCrypto> crypto;
  WVDrmPlugin plugin(&cdm, &crypto);

  const CdmClientPropertySet* propertySet = NULL;

  // Provide expected mock behavior
  {
    // Provide expected behavior in response to OpenSession and store the
    // property set
    EXPECT_CALL(cdm, OpenSession(_, _, _))
        .WillRepeatedly(DoAll(SetArgPointee<2>(cdmSessionId),
                        SaveArg<1>(&propertySet),
                        Return(wvcdm::NO_ERROR)));

    // Provide expected behavior when plugin requests session control info
    EXPECT_CALL(cdm, QueryKeyControlInfo(cdmSessionId, _))
        .WillRepeatedly(Invoke(setSessionIdOnMap<4>));

    // Let gMock know these calls will happen but we aren't interested in them.
    EXPECT_CALL(cdm, AttachEventListener(_, _))
        .Times(AtLeast(0));

    EXPECT_CALL(cdm, DetachEventListener(_, _))
        .Times(AtLeast(0));

    EXPECT_CALL(cdm, CloseSession(_))
        .Times(AtLeast(0));
  }

  status_t res;

  // Test forcing L3
  res = plugin.setPropertyString(String8("securityLevel"), String8("L3"));
  ASSERT_EQ(OK, res);

  plugin.openSession(sessionId);
  ASSERT_THAT(propertySet, NotNull());
  EXPECT_STREQ("L3", propertySet->security_level().c_str());
  plugin.closeSession(sessionId);

  // Test forcing L1 (Should Fail)
  res = plugin.setPropertyString(String8("securityLevel"), String8("L1"));
  ASSERT_NE(OK, res);

  // Test un-forcing a level
  res = plugin.setPropertyString(String8("securityLevel"), String8(""));
  ASSERT_EQ(OK, res);

  plugin.openSession(sessionId);
  ASSERT_THAT(propertySet, NotNull());
  EXPECT_STREQ("", propertySet->security_level().c_str());
  plugin.closeSession(sessionId);

  // Test nonsense (Should Fail)
  res = plugin.setPropertyString(String8("securityLevel"), String8("nonsense"));
  ASSERT_NE(OK, res);

  // Test attempting to force a level with a session open (Should Fail)
  plugin.openSession(sessionId);
  res = plugin.setPropertyString(String8("securityLevel"), String8("L3"));
  ASSERT_NE(OK, res);
}

TEST_F(WVDrmPluginTest, CanSetPrivacyMode) {
  StrictMock<MockCDM> cdm;
  StrictMock<MockCrypto> crypto;
  WVDrmPlugin plugin(&cdm, &crypto);

  const CdmClientPropertySet* propertySet = NULL;

  // Provide expected mock behavior
  {
    // Provide expected behavior in response to OpenSession and store the
    // property set
    EXPECT_CALL(cdm, OpenSession(_, _, _))
        .WillRepeatedly(DoAll(SetArgPointee<2>(cdmSessionId),
                        SaveArg<1>(&propertySet),
                        Return(wvcdm::NO_ERROR)));

    // Provide expected behavior when plugin requests session control info
    EXPECT_CALL(cdm, QueryKeyControlInfo(cdmSessionId, _))
        .WillRepeatedly(Invoke(setSessionIdOnMap<4>));

    // Let gMock know these calls will happen but we aren't interested in them.
    EXPECT_CALL(cdm, AttachEventListener(_, _))
        .Times(AtLeast(0));

    EXPECT_CALL(cdm, DetachEventListener(_, _))
        .Times(AtLeast(0));

    EXPECT_CALL(cdm, CloseSession(_))
        .Times(AtLeast(0));
  }

  plugin.openSession(sessionId);
  ASSERT_THAT(propertySet, NotNull());

  status_t res;

  // Test turning on privacy mode
  res = plugin.setPropertyString(String8("privacyMode"), String8("enable"));
  ASSERT_EQ(OK, res);
  EXPECT_TRUE(propertySet->use_privacy_mode());

  // Test turning off privacy mode
  res = plugin.setPropertyString(String8("privacyMode"), String8("disable"));
  ASSERT_EQ(OK, res);
  EXPECT_FALSE(propertySet->use_privacy_mode());

  // Test nonsense (Should Fail)
  res = plugin.setPropertyString(String8("privacyMode"), String8("nonsense"));
  ASSERT_NE(OK, res);
}

TEST_F(WVDrmPluginTest, CanSetServiceCertificate) {
  StrictMock<MockCDM> cdm;
  StrictMock<MockCrypto> crypto;
  WVDrmPlugin plugin(&cdm, &crypto);

  const CdmClientPropertySet* propertySet = NULL;

  static const size_t kPrivacyCertSize = 256;
  uint8_t privacyCertRaw[kPrivacyCertSize];

  FILE* fp = fopen("/dev/urandom", "r");
  fread(privacyCertRaw, sizeof(uint8_t), kPrivacyCertSize, fp);
  fclose(fp);

  Vector<uint8_t> privacyCert;
  privacyCert.appendArray(privacyCertRaw, kPrivacyCertSize);
  Vector<uint8_t> emptyVector;

  // Provide expected mock behavior
  {
    // Provide expected behavior in response to OpenSession and store the
    // property set
    EXPECT_CALL(cdm, OpenSession(_, _, _))
        .WillRepeatedly(DoAll(SetArgPointee<2>(cdmSessionId),
                        SaveArg<1>(&propertySet),
                        Return(wvcdm::NO_ERROR)));

    // Provide expected behavior when plugin requests session control info
    EXPECT_CALL(cdm, QueryKeyControlInfo(cdmSessionId, _))
        .WillRepeatedly(Invoke(setSessionIdOnMap<4>));

    // Let gMock know these calls will happen but we aren't interested in them.
    EXPECT_CALL(cdm, AttachEventListener(_, _))
        .Times(AtLeast(0));

    EXPECT_CALL(cdm, DetachEventListener(_, _))
        .Times(AtLeast(0));

    EXPECT_CALL(cdm, CloseSession(_))
        .Times(AtLeast(0));
  }

  plugin.openSession(sessionId);
  ASSERT_THAT(propertySet, NotNull());

  status_t res;

  // Test setting a certificate
  res = plugin.setPropertyByteArray(String8("serviceCertificate"), privacyCert);
  ASSERT_EQ(OK, res);
  EXPECT_THAT(propertySet->service_certificate(),
              ElementsAreArray(privacyCertRaw, kPrivacyCertSize));

  // Test clearing a certificate
  res = plugin.setPropertyByteArray(String8("serviceCertificate"), emptyVector);
  ASSERT_EQ(OK, res);
  EXPECT_EQ(0u, propertySet->service_certificate().size());
}

TEST_F(WVDrmPluginTest, CanSetSessionSharing) {
  StrictMock<MockCDM> cdm;
  StrictMock<MockCrypto> crypto;
  WVDrmPlugin plugin(&cdm, &crypto);

  const CdmClientPropertySet* propertySet = NULL;

  // Provide expected mock behavior
  {
    // Provide expected behavior in response to OpenSession and store the
    // property set
    EXPECT_CALL(cdm, OpenSession(_, _, _))
        .WillRepeatedly(DoAll(SetArgPointee<2>(cdmSessionId),
                        SaveArg<1>(&propertySet),
                        Return(wvcdm::NO_ERROR)));

    // Provide expected behavior when plugin requests session control info
    EXPECT_CALL(cdm, QueryKeyControlInfo(cdmSessionId, _))
        .WillRepeatedly(Invoke(setSessionIdOnMap<4>));

    // Let gMock know these calls will happen but we aren't interested in them.
    EXPECT_CALL(cdm, AttachEventListener(_, _))
        .Times(AtLeast(0));

    EXPECT_CALL(cdm, DetachEventListener(_, _))
        .Times(AtLeast(0));

    EXPECT_CALL(cdm, CloseSession(_))
        .Times(AtLeast(0));
  }

  status_t res;

  // Test turning on session sharing
  res = plugin.setPropertyString(String8("sessionSharing"), String8("enable"));
  ASSERT_EQ(OK, res);

  plugin.openSession(sessionId);
  ASSERT_THAT(propertySet, NotNull());
  EXPECT_TRUE(propertySet->is_session_sharing_enabled());
  plugin.closeSession(sessionId);

  // Test turning off session sharing
  res = plugin.setPropertyString(String8("sessionSharing"), String8("disable"));
  ASSERT_EQ(OK, res);

  plugin.openSession(sessionId);
  ASSERT_THAT(propertySet, NotNull());
  EXPECT_FALSE(propertySet->is_session_sharing_enabled());
  plugin.closeSession(sessionId);

  // Test nonsense (Should Fail)
  res = plugin.setPropertyString(String8("sessionSharing"), String8("nonsense"));
  ASSERT_NE(OK, res);

  // Test changing sharing with a session open (Should Fail)
  plugin.openSession(sessionId);
  res = plugin.setPropertyString(String8("sessionSharing"), String8("enable"));
  ASSERT_NE(OK, res);
}

TEST_F(WVDrmPluginTest, AllowsStoringOfSessionSharingId) {
  StrictMock<MockCDM> cdm;
  StrictMock<MockCrypto> crypto;
  WVDrmPlugin plugin(&cdm, &crypto);

  CdmClientPropertySet* propertySet = NULL;

  uint32_t sharingId;
  FILE* fp = fopen("/dev/urandom", "r");
  fread(&sharingId, sizeof(uint32_t), 1, fp);
  fclose(fp);

  // Provide expected mock behavior
  {
    // Provide expected behavior in response to OpenSession and store the
    // property set
    EXPECT_CALL(cdm, OpenSession(_, _, _))
        .WillRepeatedly(DoAll(SetArgPointee<2>(cdmSessionId),
                        SaveArg<1>(&propertySet),
                        Return(wvcdm::NO_ERROR)));

    // Provide expected behavior when plugin requests session control info
    EXPECT_CALL(cdm, QueryKeyControlInfo(cdmSessionId, _))
        .WillRepeatedly(Invoke(setSessionIdOnMap<4>));

    // Let gMock know these calls will happen but we aren't interested in them.
    EXPECT_CALL(cdm, AttachEventListener(_, _))
        .Times(AtLeast(0));

    EXPECT_CALL(cdm, DetachEventListener(_, _))
        .Times(AtLeast(0));

    EXPECT_CALL(cdm, CloseSession(_))
        .Times(AtLeast(0));
  }

  plugin.openSession(sessionId);

  ASSERT_THAT(propertySet, NotNull());
  propertySet->set_session_sharing_id(sharingId);
  EXPECT_EQ(sharingId, propertySet->session_sharing_id());
}
