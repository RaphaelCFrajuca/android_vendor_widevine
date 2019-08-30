// Copyright 2012 Google Inc. All Rights Reserved.

#include "crypto_session.h"
#include "license.h"
#include "gtest/gtest.h"
#include "policy_engine.h"
#include "string_conversions.h"

namespace {

// The test data is based on key box Eureka-Dev-G1-0001520
// This unit test should run on oemcrypto mock with the same key box
static const char* kInitData = "0801121093789920E8D6520098577DF8F2DD5546";
static const char* kSignedRequest =
    "080112790A4C0800124800000002000001241F344DB9DFF087F01D917910F39B"
    "60DC7797CD97789EE82516DC07A478CB70B8C08C299293150AA8E01D2DC9808C"
    "98DAA16E40A0E55DFE3618C7584DD3C7BE4212250A230A140801121093789920"
    "E8D6520098577DF8F2DD554610011A09393837363534333231180120001A20FA"
    "E2DDCD7F1ACA4B728EC957FEE802F8A5541557ACA784EE0D05BFCC0E65FEA1";
static const char* kValidResponse =
    "080212D9020A190A093938373635343332311208C434AB9240A9EF2420012800"
    "120E0801180120809A9E0128809A9E011A461210B72EEBF582B04BDB15C2E0E3"
    "20B21C351A30E51FC1D27F70DB8E0DDF8C051BD6E251A44599DBCE4E1BE663FD"
    "3AFAB191A7DD5736841FB04CE558E7F17BD9812A2DBA20011A6E0A1093789920"
    "E8D6520098577DF8F2DD55461210367E8714B6F10087AFDE542EDC5C91541A20"
    "ED51D4E84D81C8CBD8E2046EE079F8A2016268A2F192B902FDA241FEEB10C014"
    "200242240A109209D46191B8752147C9F6A1CE2BEE6E12107910F39B60DC7797"
    "CD97789EE82516DC1A6E0A107B1328EB61B554E293F75B1E3E94CC3B1210676F"
    "69BBDA35EE972B77BC1328A087391A20D2B9FA92B164F5F6362CAD9200A11661"
    "B8F71E9CE671A3A252D34586526B68FA200242240A109D7B13420FD6217666CC"
    "CD43860FAA3A1210DBCE4E1BE663FD3AFAB191A7DD57368420E9FDCE86051A20"
    "C6279E32FD2CB9067229E87AFF4B2DE14A077CDF8F061DAEE2CC2D1BCDEF62D0";
static const char* kInvalidResponse =
    "0802128D020A190A093938373635343332311208BA68C949396C438C20012800"
    "120E0801180120809A9E0128809A9E011A4612105021EB9AEDC1F73E96DE7DCC"
    "6D7D72401A300A82E118C0BF0DB230FCADE3F49A9777DDD392322240FEF32C97"
    "F85428E2F6CCFA638B5481464ADBCF199CEC2FCF3AFB20011A480A1093789920"
    "E8D6520098577DF8F2DD55461210EE52C59B99050A36E10569AFB34D1DA41A20"
    "C61FCB8019AC9ADE99FF8FCA99ED35E2331B6488A35102F9379AA42C87A22DC7"
    "20021A480A107B1328EB61B554E293F75B1E3E94CC3B12101BBF5286B859E349"
    "2E4A47A24C06AC1B1A2061F21836A04E558BEE0244EF41C165F60CF23C580275"
    "3175D48BAF1C6CA5759F200220A2BCCA86051A203FD4671075D9DEC6486A9317"
    "70669993306831EDD57D77F34EFEB467470BA364";
}

namespace wvcdm {

class LicenseTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    session_ = new CryptoSession();
    EXPECT_TRUE(session_ != NULL);

    std::string token;
    EXPECT_TRUE(session_->GetToken(&token));

    EXPECT_TRUE(session_->Open());
    EXPECT_TRUE(license_.Init(token, session_, &policy_engine_));
  }

  virtual void TearDown() {
    session_->Close();
    delete session_;
  }

  CryptoSession* session_;
  CdmLicense license_;
  PolicyEngine policy_engine_;
};

TEST(LicenseTestSession, InitNullSession) {
  CdmLicense license;
  EXPECT_FALSE(license.Init("Dummy", NULL, NULL));
}

// TODO(rfrias): Fix or remove test.
TEST_F(LicenseTest, DISABLED_PrepareKeyRequest) {
  std::string signed_request;
  CdmAppParameterMap app_parameters;
  std::string server_url;
  CdmSessionId session_id;
  license_.PrepareKeyRequest(a2bs_hex(kInitData),
                             kLicenseTypeStreaming,
                             app_parameters,
                             session_id,
                             &signed_request,
                             &server_url);
  EXPECT_EQ(signed_request, a2bs_hex(kSignedRequest));
}

// TODO(rfrias): Fix or remove test.
TEST_F(LicenseTest, DISABLED_HandleKeyResponseValid) {
  std::string signed_request;
  CdmAppParameterMap app_parameters;
  CdmSessionId session_id;
  std::string server_url;
  license_.PrepareKeyRequest(a2bs_hex(kInitData),
                             kLicenseTypeStreaming,
                             app_parameters,
                             session_id,
                             &signed_request,
                             &server_url);
  EXPECT_EQ(signed_request, a2bs_hex(kSignedRequest));
  EXPECT_TRUE(license_.HandleKeyResponse(a2bs_hex(kValidResponse)));
}

// TODO(rfrias): Fix or remove test.
TEST_F(LicenseTest, DISABLED_HandleKeyResponseInvalid) {
  std::string signed_request;
  CdmAppParameterMap app_parameters;
  CdmSessionId session_id;
  std::string server_url;
  license_.PrepareKeyRequest(a2bs_hex(kInitData),
                             kLicenseTypeStreaming,
                             app_parameters,
                             session_id,
                             &signed_request,
                             &server_url);
  EXPECT_EQ(signed_request, a2bs_hex(kSignedRequest));
  EXPECT_FALSE(license_.HandleKeyResponse(a2bs_hex(kInvalidResponse)));
}

// TODO(kqyang): add unit test cases for PrepareKeyRenewalRequest
// and HandleRenewalKeyResponse

}
