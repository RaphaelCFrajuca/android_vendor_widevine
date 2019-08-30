//
// Copyright 2013 Google Inc. All Rights Reserved.
//

#include <stdio.h>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "media/stagefright/foundation/ABase.h"
#include "media/stagefright/foundation/AString.h"
#include "OEMCryptoCENC.h"
#include "wv_cdm_constants.h"
#include "wv_cdm_types.h"
#include "wv_content_decryption_module.h"
#include "WVCryptoPlugin.h"

using namespace android;
using namespace std;
using namespace testing;
using namespace wvcdm;
using namespace wvdrm;

class MockCDM : public WvContentDecryptionModule {
 public:
  MOCK_METHOD2(Decrypt, CdmResponseType(const CdmSessionId&,
                                        const CdmDecryptionParameters&));

  MOCK_METHOD2(QuerySessionStatus, CdmResponseType(const CdmSessionId&,
                                                   CdmQueryMap*));
};

class WVCryptoPluginTest : public Test {
 protected:
  static const uint32_t kSessionIdSize = 16;
  uint8_t sessionId[kSessionIdSize];

  virtual void SetUp() {
    FILE* fp = fopen("/dev/urandom", "r");
    fread(sessionId, sizeof(uint8_t), kSessionIdSize, fp);
    fclose(fp);

    // Set default CdmResponseType value for gMock
    DefaultValue<CdmResponseType>::Set(wvcdm::NO_ERROR);
  }
};

TEST_F(WVCryptoPluginTest, CorrectlyReportsSecureBuffers) {
  StrictMock<MockCDM> cdm;
  WVCryptoPlugin plugin(sessionId, kSessionIdSize, &cdm);

  CdmQueryMap l1Map;
  l1Map[QUERY_KEY_SECURITY_LEVEL] = QUERY_VALUE_SECURITY_LEVEL_L1;

  CdmQueryMap l3Map;
  l3Map[QUERY_KEY_SECURITY_LEVEL] = QUERY_VALUE_SECURITY_LEVEL_L3;

  EXPECT_CALL(cdm, QuerySessionStatus(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(l1Map),
                      Return(wvcdm::NO_ERROR)))
      .WillOnce(DoAll(SetArgPointee<1>(l3Map),
                      Return(wvcdm::NO_ERROR)));

  EXPECT_TRUE(plugin.requiresSecureDecoderComponent("video/mp4")) <<
      "WVCryptoPlugin incorrectly allows an insecure video decoder on L1";
  EXPECT_FALSE(plugin.requiresSecureDecoderComponent("video/mp4")) <<
      "WVCryptoPlugin incorrectly expects a secure video decoder on L3";
  EXPECT_FALSE(plugin.requiresSecureDecoderComponent("audio/aac")) <<
      "WVCryptoPlugin incorrectly expects a secure audio decoder";
}

// Factory for matchers that perform deep matching of values against a
// CdmDecryptionParameters struct. For use in the test AttemptsToDecrypt.
class CDPMatcherFactory {
  public:
    // Some values do not change over the course of the test.  To avoid having
    // to re-specify them at every call site, we pass them into the factory
    // constructor.
    CDPMatcherFactory(bool isSecure, uint8_t* keyId, void* out, size_t outLen)
        : mIsSecure(isSecure), mKeyId(keyId), mOut(out), mOutLen(outLen) {}

    Matcher<const CdmDecryptionParameters&> operator()(bool isEncrypted,
                                                       uint8_t* in,
                                                       size_t inLen,
                                                       uint8_t* iv,
                                                       size_t blockOffset,
                                                       size_t outOffset,
                                                       uint8_t flags) const {
      return Truly(CDPMatcher(mIsSecure, mKeyId, mOut, mOutLen, isEncrypted,
                              in, inLen, iv, blockOffset, outOffset, flags));
    }

  private:
    // Predicate that validates that the fields of a passed-in
    // CdmDecryptionParameters match the values it was given at construction
    // time.
    class CDPMatcher {
      public:
        CDPMatcher(bool isSecure, uint8_t* keyId, void* out, size_t outLen,
                   bool isEncrypted, uint8_t* in, size_t inLen, uint8_t* iv,
                   size_t blockOffset, size_t outOffset, uint8_t flags)
            : mIsSecure(isSecure), mKeyId(keyId), mOut(out), mOutLen(outLen),
              mIsEncrypted(isEncrypted), mIn(in), mInLen(inLen), mIv(iv),
              mBlockOffset(blockOffset), mOutOffset(outOffset), mFlags(flags) {}

        bool operator()(const CdmDecryptionParameters& params) const {
          return params.is_secure == mIsSecure &&
                 Value(*params.key_id, ElementsAreArray(mKeyId, KEY_ID_SIZE)) &&
                 params.decrypt_buffer == mOut &&
                 params.decrypt_buffer_length == mOutLen &&
                 params.is_encrypted == mIsEncrypted &&
                 params.encrypt_buffer == mIn &&
                 params.encrypt_length == mInLen &&
                 Value(*params.iv, ElementsAreArray(mIv, KEY_IV_SIZE)) &&
                 params.block_offset == mBlockOffset &&
                 params.decrypt_buffer_offset == mOutOffset &&
                 params.subsample_flags == mFlags;
        }

      private:
        bool mIsSecure;
        uint8_t* mKeyId;
        void* mOut;
        size_t mOutLen;
        bool mIsEncrypted;
        uint8_t* mIn;
        size_t mInLen;
        uint8_t* mIv;
        size_t mBlockOffset;
        size_t mOutOffset;
        uint8_t mFlags;
    };

    bool mIsSecure;
    uint8_t* mKeyId;
    void* mOut;
    size_t mOutLen;
};

TEST_F(WVCryptoPluginTest, AttemptsToDecrypt) {
  StrictMock<MockCDM> cdm;
  WVCryptoPlugin plugin(sessionId, kSessionIdSize, &cdm);

  uint8_t keyId[KEY_ID_SIZE];
  uint8_t baseIv[KEY_IV_SIZE];

  static const size_t kDataSize = 185;
  uint8_t in[kDataSize];
  uint8_t out[kDataSize];

  FILE* fp = fopen("/dev/urandom", "r");
  fread(keyId, sizeof(uint8_t), KEY_ID_SIZE, fp);
  fread(baseIv, sizeof(uint8_t), KEY_IV_SIZE, fp);
  fread(in, sizeof(uint8_t), kDataSize, fp);
  fclose(fp);

  static const size_t kSubSampleCount = 6;
  CryptoPlugin::SubSample subSamples[kSubSampleCount];
  memset(subSamples, 0, sizeof(subSamples));
  subSamples[0].mNumBytesOfEncryptedData = 16;
  subSamples[1].mNumBytesOfClearData = 16;
  subSamples[1].mNumBytesOfEncryptedData = 16;
  subSamples[2].mNumBytesOfEncryptedData = 8;
  subSamples[3].mNumBytesOfClearData = 29;
  subSamples[3].mNumBytesOfEncryptedData = 24;
  subSamples[4].mNumBytesOfEncryptedData = 60;
  subSamples[5].mNumBytesOfEncryptedData = 16;

  uint8_t iv[5][KEY_IV_SIZE];
  memcpy(iv[0], baseIv, sizeof(baseIv));
  iv[0][15] = 0;
  memcpy(iv[1], baseIv, sizeof(baseIv));
  iv[1][15] = 1;
  memcpy(iv[2], baseIv, sizeof(baseIv));
  iv[2][15] = 2;
  memcpy(iv[3], baseIv, sizeof(baseIv));
  iv[3][15] = 4;
  memcpy(iv[4], baseIv, sizeof(baseIv));
  iv[4][15] = 7;

  CDPMatcherFactory ParamsAre = CDPMatcherFactory(false, keyId, out, kDataSize);

  {
    InSequence calls;

    // SubSample 0
    EXPECT_CALL(cdm, Decrypt(ElementsAreArray(sessionId, kSessionIdSize),
                             ParamsAre(true, in, 16, iv[0], 0, 0,
                                       OEMCrypto_FirstSubsample)))
        .Times(1);

    // SubSample 1
    EXPECT_CALL(cdm, Decrypt(ElementsAreArray(sessionId, kSessionIdSize),
                             ParamsAre(false, in + 16, 16, iv[1], 0, 16, 0)))
        .Times(1);

    EXPECT_CALL(cdm, Decrypt(ElementsAreArray(sessionId, kSessionIdSize),
                             ParamsAre(true, in + 32, 16, iv[1], 0, 32, 0)))
        .Times(1);

    // SubSample 2
    EXPECT_CALL(cdm, Decrypt(ElementsAreArray(sessionId, kSessionIdSize),
                             ParamsAre(true, in + 48, 8, iv[2], 0, 48, 0)))
        .Times(1);

    // SubSample 3
    EXPECT_CALL(cdm, Decrypt(ElementsAreArray(sessionId, kSessionIdSize),
                             ParamsAre(false, in + 56, 29, iv[2], 0, 56, 0)))
        .Times(1);

    EXPECT_CALL(cdm, Decrypt(ElementsAreArray(sessionId, kSessionIdSize),
                             ParamsAre(true, in + 85, 24, iv[2], 8, 85, 0)))
        .Times(1);

    // SubSample 4
    EXPECT_CALL(cdm, Decrypt(ElementsAreArray(sessionId, kSessionIdSize),
                             ParamsAre(true, in + 109, 60, iv[3], 0, 109, 0)))
        .Times(1);

    // SubSample 5
    EXPECT_CALL(cdm, Decrypt(ElementsAreArray(sessionId, kSessionIdSize),
                             ParamsAre(true, in + 169, 16, iv[4], 12, 169,
                                       OEMCrypto_LastSubsample)))
        .Times(1);
  }

  AString errorDetailMessage;

  ssize_t res = plugin.decrypt(false, keyId, iv[0], CryptoPlugin::kMode_AES_CTR,
                               in, subSamples, kSubSampleCount, out,
                               &errorDetailMessage);

  EXPECT_EQ(static_cast<ssize_t>(kDataSize), res) <<
      "WVCryptoPlugin decrypted the wrong number of bytes";
  EXPECT_EQ(0u, errorDetailMessage.size()) <<
      "WVCryptoPlugin reported a detailed error message.";
}

TEST_F(WVCryptoPluginTest, CommunicatesSecureBufferRequest) {
  StrictMock<MockCDM> cdm;
  WVCryptoPlugin plugin(sessionId, kSessionIdSize, &cdm);

  uint8_t keyId[KEY_ID_SIZE];
  uint8_t iv[KEY_IV_SIZE];

  static const size_t kDataSize = 32;
  uint8_t in[kDataSize];
  uint8_t out[kDataSize];

  FILE* fp = fopen("/dev/urandom", "r");
  fread(keyId, sizeof(uint8_t), KEY_ID_SIZE, fp);
  fread(iv, sizeof(uint8_t), KEY_IV_SIZE, fp);
  fread(in, sizeof(uint8_t), kDataSize, fp);
  fclose(fp);

  static const uint32_t kSubSampleCount = 1;
  CryptoPlugin::SubSample subSamples[kSubSampleCount];
  memset(subSamples, 0, sizeof(subSamples));
  subSamples[0].mNumBytesOfClearData = 16;
  subSamples[0].mNumBytesOfEncryptedData = 16;

  // Specify the expected calls to Decrypt
  {
    InSequence calls;

    typedef CdmDecryptionParameters CDP;

    EXPECT_CALL(cdm, Decrypt(_, Field(&CDP::is_secure, false)))
        .Times(2);

    EXPECT_CALL(cdm, Decrypt(_, Field(&CDP::is_secure, true)))
        .Times(2);
  }

  AString errorDetailMessage;

  ssize_t res = plugin.decrypt(false, keyId, iv, CryptoPlugin::kMode_AES_CTR,
                               in, subSamples, kSubSampleCount, out,
                               &errorDetailMessage);
  ASSERT_GE(res, 0) <<
      "WVCryptoPlugin returned an error";
  EXPECT_EQ(0u, errorDetailMessage.size()) <<
      "WVCryptoPlugin reported a detailed error message.";

  res = plugin.decrypt(true, keyId, iv, CryptoPlugin::kMode_AES_CTR, in,
                       subSamples, kSubSampleCount, out, &errorDetailMessage);
  ASSERT_GE(res, 0) <<
      "WVCryptoPlugin returned an error";
  EXPECT_EQ(0u, errorDetailMessage.size()) <<
      "WVCryptoPlugin reported a detailed error message.";
}

TEST_F(WVCryptoPluginTest, SetsFlagsForMinimumSubsampleRuns) {
  MockCDM cdm;
  WVCryptoPlugin plugin(sessionId, kSessionIdSize, &cdm);

  uint8_t keyId[KEY_ID_SIZE];
  uint8_t iv[KEY_IV_SIZE];

  static const size_t kDataSize = 16;
  uint8_t in[kDataSize];
  uint8_t out[kDataSize];

  FILE* fp = fopen("/dev/urandom", "r");
  fread(keyId, sizeof(uint8_t), KEY_ID_SIZE, fp);
  fread(iv, sizeof(uint8_t), KEY_IV_SIZE, fp);
  fread(in, sizeof(uint8_t), kDataSize, fp);
  fclose(fp);

  static const uint32_t kSubSampleCount = 1;
  CryptoPlugin::SubSample clearSubSamples[kSubSampleCount];
  memset(clearSubSamples, 0, sizeof(clearSubSamples));
  clearSubSamples[0].mNumBytesOfClearData = 16;

  CryptoPlugin::SubSample encryptedSubSamples[kSubSampleCount];
  memset(encryptedSubSamples, 0, sizeof(encryptedSubSamples));
  encryptedSubSamples[0].mNumBytesOfEncryptedData = 16;

  CryptoPlugin::SubSample mixedSubSamples[kSubSampleCount];
  memset(mixedSubSamples, 0, sizeof(mixedSubSamples));
  mixedSubSamples[0].mNumBytesOfClearData = 8;
  mixedSubSamples[0].mNumBytesOfEncryptedData = 8;

  // Specify the expected calls to Decrypt
  {
    InSequence calls;

    typedef CdmDecryptionParameters CDP;

    EXPECT_CALL(cdm, Decrypt(_, Field(&CDP::subsample_flags,
                                      OEMCrypto_FirstSubsample |
                                          OEMCrypto_LastSubsample)))
        .Times(2);

    EXPECT_CALL(cdm, Decrypt(_, Field(&CDP::subsample_flags,
                                      OEMCrypto_FirstSubsample)))
        .Times(1);

    EXPECT_CALL(cdm, Decrypt(_, Field(&CDP::subsample_flags,
                                      OEMCrypto_LastSubsample)))
        .Times(1);
  }

  AString errorDetailMessage;

  ssize_t res = plugin.decrypt(false, keyId, iv, CryptoPlugin::kMode_AES_CTR,
                               in, clearSubSamples, kSubSampleCount, out,
                               &errorDetailMessage);
  ASSERT_GE(res, 0) <<
      "WVCryptoPlugin returned an error";
  EXPECT_EQ(0u, errorDetailMessage.size()) <<
      "WVCryptoPlugin reported a detailed error message.";

  res = plugin.decrypt(false, keyId, iv, CryptoPlugin::kMode_AES_CTR, in,
                       encryptedSubSamples, kSubSampleCount, out,
                       &errorDetailMessage);
  ASSERT_GE(res, 0) <<
      "WVCryptoPlugin returned an error";
  EXPECT_EQ(0u, errorDetailMessage.size()) <<
      "WVCryptoPlugin reported a detailed error message.";

  res = plugin.decrypt(false, keyId, iv, CryptoPlugin::kMode_AES_CTR, in,
                       mixedSubSamples, kSubSampleCount, out,
                       &errorDetailMessage);
  ASSERT_GE(res, 0) <<
      "WVCryptoPlugin returned an error";
  EXPECT_EQ(0u, errorDetailMessage.size()) <<
      "WVCryptoPlugin reported a detailed error message.";
}
