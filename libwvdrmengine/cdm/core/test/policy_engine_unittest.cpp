// Copyright 2012 Google Inc. All Rights Reserved.

#include <sstream>

#include "clock.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "license.h"
#include "policy_engine.h"
#include "wv_cdm_constants.h"

namespace wvcdm {

//protobuf generated classes.
using video_widevine_server::sdk::License;
using video_widevine_server::sdk::License_Policy;
using video_widevine_server::sdk::LicenseIdentification;
using video_widevine_server::sdk::STREAMING;
using video_widevine_server::sdk::OFFLINE;

// gmock methods
using ::testing::Return;
using ::testing::AtLeast;


class MockClock : public Clock {
 public:
  MOCK_METHOD0(GetCurrentTime, int64_t());
};

class PolicyEngineTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    mock_clock_ = new MockClock();
    policy_engine_ = new PolicyEngine(mock_clock_);

    license_start_time_ = 1413517500;             // ~ 01/01/2013
    license_renewal_delay_ = 604200;              // 7 days - 10 minutes
    license_renewal_retry_interval_ = 30;
    license_duration_ = 604800;                   // 7 days
    playback_duration_ = 86400;                   // 24 hours

    license_.set_license_start_time(license_start_time_);

    LicenseIdentification* id = license_.mutable_id();
    id->set_version(1);
    id->set_type(STREAMING);

    License_Policy* policy = license_.mutable_policy();
    policy = license_.mutable_policy();
    policy->set_can_play(true);
    policy->set_can_persist(true);
    policy->set_can_renew(true);
    policy->set_rental_duration_seconds(license_duration_);
    policy->set_playback_duration_seconds(playback_duration_);
    policy->set_license_duration_seconds(license_duration_);
    policy->set_renewal_recovery_duration_seconds(license_duration_ -
        license_renewal_delay_);                  // 10 minutes
    policy->set_renewal_server_url(
        "https://jmt17.google.com/video-dev/license/GetCencLicense");
    policy->set_renewal_delay_seconds(license_renewal_delay_);
    policy->set_renewal_retry_interval_seconds(
        license_renewal_retry_interval_);
    policy->set_renew_with_usage(false);
  }

  virtual void TearDown() {
    delete policy_engine_;
    // Done by policy engine: delete mock_clock_;
    policy_engine_ = NULL;
    mock_clock_ = NULL;
  }

  MockClock* mock_clock_;
  PolicyEngine* policy_engine_;
  License license_;
  License_Policy* policy_;

  int64_t license_start_time_;
  int64_t license_renewal_delay_;
  int64_t license_renewal_retry_interval_;
  int64_t license_duration_;
  int64_t playback_duration_;
};

TEST_F(PolicyEngineTest, NoLicense) {
  EXPECT_FALSE(policy_engine_->can_decrypt());
}

TEST_F(PolicyEngineTest, PlaybackSuccess) {
  EXPECT_CALL(*mock_clock_, GetCurrentTime())
      .WillOnce(Return(license_start_time_ + 1))
      .WillOnce(Return(license_start_time_ + 5))
      .WillOnce(Return(license_start_time_ + 10));

  policy_engine_->SetLicense(license_);

  bool event_occurred;
  CdmEventType event;
  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  policy_engine_->BeginDecryption();
  EXPECT_TRUE(policy_engine_->can_decrypt());
}

TEST_F(PolicyEngineTest, PlaybackFailed_CanPlayFalse) {
  EXPECT_CALL(*mock_clock_, GetCurrentTime())
      .WillOnce(Return(license_start_time_ + 5));

  License_Policy* policy = license_.mutable_policy();
  policy->set_can_play(false);

  policy_engine_->SetLicense(license_);

  bool event_occurred;
  CdmEventType event;
  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  policy_engine_->BeginDecryption();
  EXPECT_FALSE(policy_engine_->can_decrypt());
}

// TODO(edwinwong, rfrias): persist license verification test needed

TEST_F(PolicyEngineTest, PlaybackFails_RentalDurationExpired) {
  EXPECT_CALL(*mock_clock_, GetCurrentTime())
      .WillOnce(Return(license_start_time_ + 1))
      .WillOnce(Return(license_start_time_ + 5))
      .WillOnce(Return(license_start_time_ + 3600))
      .WillOnce(Return(license_start_time_ + 3601));

  License_Policy* policy = license_.mutable_policy();
  policy->set_rental_duration_seconds(3600);

  policy_engine_->SetLicense(license_);

  policy_engine_->BeginDecryption();
  EXPECT_TRUE(policy_engine_->can_decrypt());

  bool event_occurred;
  CdmEventType event;
  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_TRUE(event_occurred);
  EXPECT_EQ(LICENSE_EXPIRED_EVENT, event);

  EXPECT_FALSE(policy_engine_->can_decrypt());
}

// TODO(edwinwong, rfrias): tests needed when begin license usage when received
//     is enabled

TEST_F(PolicyEngineTest, PlaybackFails_PlaybackDurationExpired) {
  EXPECT_CALL(*mock_clock_, GetCurrentTime())
      .WillOnce(Return(license_start_time_ + 1))
      .WillOnce(Return(license_start_time_ + 10000))
      .WillOnce(Return(license_start_time_ + 13598))
      .WillOnce(Return(license_start_time_ + 13602));

  License_Policy* policy = license_.mutable_policy();
  policy->set_playback_duration_seconds(3600);

  policy_engine_->SetLicense(license_);

  policy_engine_->BeginDecryption();
  EXPECT_TRUE(policy_engine_->can_decrypt());

  bool event_occurred;
  CdmEventType event;
  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_TRUE(event_occurred);
  EXPECT_EQ(LICENSE_EXPIRED_EVENT, event);

  EXPECT_FALSE(policy_engine_->can_decrypt());
}

TEST_F(PolicyEngineTest, PlaybackFails_LicenseDurationExpired) {
  EXPECT_CALL(*mock_clock_, GetCurrentTime())
      .WillOnce(Return(license_start_time_ + 1))
      .WillOnce(Return(license_start_time_ + 5))
      .WillOnce(Return(license_start_time_ + 3600))
      .WillOnce(Return(license_start_time_ + 3601));

  License_Policy* policy = license_.mutable_policy();
  policy->set_license_duration_seconds(3600);

  policy_engine_->SetLicense(license_);

  policy_engine_->BeginDecryption();
  EXPECT_TRUE(policy_engine_->can_decrypt());

  bool event_occurred;
  CdmEventType event;
  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_TRUE(event_occurred);
  EXPECT_EQ(LICENSE_EXPIRED_EVENT, event);

  EXPECT_FALSE(policy_engine_->can_decrypt());
}

TEST_F(PolicyEngineTest, PlaybackOk_RentalDuration0) {
  EXPECT_CALL(*mock_clock_, GetCurrentTime())
      .WillOnce(Return(license_start_time_ + 1))
      .WillOnce(Return(license_start_time_ + 5))
      .WillOnce(Return(license_start_time_ + 3600))
      .WillOnce(Return(license_start_time_ + 3601));

  License_Policy* policy = license_.mutable_policy();
  policy->set_rental_duration_seconds(0);
  policy->set_license_duration_seconds(3600);

  policy_engine_->SetLicense(license_);

  policy_engine_->BeginDecryption();
  EXPECT_TRUE(policy_engine_->can_decrypt());

  bool event_occurred;
  CdmEventType event;
  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_TRUE(event_occurred);
  EXPECT_EQ(LICENSE_EXPIRED_EVENT, event);

  EXPECT_FALSE(policy_engine_->can_decrypt());
}

TEST_F(PolicyEngineTest, PlaybackOk_PlaybackDuration0) {
  EXPECT_CALL(*mock_clock_, GetCurrentTime())
      .WillOnce(Return(license_start_time_ + 10000))
      .WillOnce(Return(license_start_time_ + 10005))
      .WillOnce(Return(license_start_time_ + 13598))
      .WillOnce(Return(license_start_time_ + 13602));

  License_Policy* policy = license_.mutable_policy();
  policy->set_playback_duration_seconds(0);
  policy->set_license_duration_seconds(3600);

  policy_engine_->SetLicense(license_);

  policy_engine_->BeginDecryption();
  EXPECT_TRUE(policy_engine_->can_decrypt());

  bool event_occurred;
  CdmEventType event;
  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_TRUE(event_occurred);
  EXPECT_EQ(LICENSE_EXPIRED_EVENT, event);

  EXPECT_FALSE(policy_engine_->can_decrypt());
}

TEST_F(PolicyEngineTest, PlaybackOk_LicenseDuration0) {
  EXPECT_CALL(*mock_clock_, GetCurrentTime())
      .WillOnce(Return(license_start_time_ + 1))
      .WillOnce(Return(license_start_time_ + 5))
      .WillOnce(Return(license_start_time_ + 3600))
      .WillOnce(Return(license_start_time_ + 3601));

  License_Policy* policy = license_.mutable_policy();
  policy->set_license_duration_seconds(0);
  policy->set_rental_duration_seconds(3600);

  policy_engine_->SetLicense(license_);

  policy_engine_->BeginDecryption();
  EXPECT_TRUE(policy_engine_->can_decrypt());

  bool event_occurred;
  CdmEventType event;
  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_TRUE(event_occurred);
  EXPECT_EQ(LICENSE_EXPIRED_EVENT, event);

  EXPECT_FALSE(policy_engine_->can_decrypt());
}

TEST_F(PolicyEngineTest, PlaybackOk_Durations0) {
  EXPECT_CALL(*mock_clock_, GetCurrentTime())
      .WillOnce(Return(license_start_time_ + 1))
      .WillOnce(Return(license_start_time_ + 5))
      .WillOnce(Return(license_start_time_ + 604800))
      .WillOnce(Return(license_start_time_ + 604810));

  License_Policy* policy = license_.mutable_policy();
  policy->set_rental_duration_seconds(0);
  policy->set_playback_duration_seconds(0);
  policy->set_license_duration_seconds(0);
  policy->set_renewal_delay_seconds(604900);

  policy_engine_->SetLicense(license_);

  policy_engine_->BeginDecryption();
  EXPECT_TRUE(policy_engine_->can_decrypt());

  bool event_occurred;
  CdmEventType event;
  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  EXPECT_TRUE(policy_engine_->can_decrypt());
}


// TODO(edwinwong, rfrias): renewal url test needed

TEST_F(PolicyEngineTest, PlaybackFailed_CanRenewFalse) {
  EXPECT_CALL(*mock_clock_, GetCurrentTime())
      .WillOnce(Return(license_start_time_ + 1))
      .WillOnce(Return(license_start_time_ + license_duration_ -
          playback_duration_ + 1))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ - 10))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ + 10))
      .WillOnce(Return(license_start_time_ + license_duration_ + 10));

  License_Policy* policy = license_.mutable_policy();
  policy->set_can_renew(false);

  policy_engine_->SetLicense(license_);

  policy_engine_->BeginDecryption();
  EXPECT_TRUE(policy_engine_->can_decrypt());

  bool event_occurred;
  CdmEventType event;
  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_TRUE(event_occurred);
  EXPECT_EQ(LICENSE_EXPIRED_EVENT, event);

  EXPECT_FALSE(policy_engine_->can_decrypt());
}

TEST_F(PolicyEngineTest, PlaybackOk_RenewSuccess) {
  EXPECT_CALL(*mock_clock_, GetCurrentTime())
      .WillOnce(Return(license_start_time_ + 1))
      .WillOnce(Return(license_start_time_ + license_duration_ -
          playback_duration_ + 1))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ - 15))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ + 10))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ + 20))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ +
          license_renewal_retry_interval_ + 10));

  policy_engine_->SetLicense(license_);

  policy_engine_->BeginDecryption();
  EXPECT_TRUE(policy_engine_->can_decrypt());

  bool event_occurred;
  CdmEventType event;
  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_TRUE(event_occurred);
  EXPECT_EQ(LICENSE_RENEWAL_NEEDED_EVENT, event);

  EXPECT_TRUE(policy_engine_->can_decrypt());

  license_.set_license_start_time(license_start_time_ +
                                  license_renewal_delay_ + 15);
  LicenseIdentification* id = license_.mutable_id();
  id->set_version(2);
  policy_engine_->UpdateLicense(license_);

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  EXPECT_TRUE(policy_engine_->can_decrypt());
}

TEST_F(PolicyEngineTest, PlaybackFailed_RenewFailedVersionNotUpdated) {
  EXPECT_CALL(*mock_clock_, GetCurrentTime())
      .WillOnce(Return(license_start_time_ + 1))
      .WillOnce(Return(license_start_time_ + license_duration_ -
          playback_duration_ + 1))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ - 10))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ + 10))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ + 40))
      .WillOnce(Return(license_start_time_ + license_duration_ + 10));

  policy_engine_->SetLicense(license_);

  policy_engine_->BeginDecryption();
  EXPECT_TRUE(policy_engine_->can_decrypt());

  bool event_occurred;
  CdmEventType event;
  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_TRUE(event_occurred);
  EXPECT_EQ(LICENSE_RENEWAL_NEEDED_EVENT, event);

  EXPECT_TRUE(policy_engine_->can_decrypt());

  license_.set_license_start_time(license_start_time_ +
                                  license_renewal_delay_ + 15);
  policy_engine_->UpdateLicense(license_);

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_TRUE(event_occurred);
  EXPECT_EQ(LICENSE_RENEWAL_NEEDED_EVENT, event);

  EXPECT_TRUE(policy_engine_->can_decrypt());

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_TRUE(event_occurred);
  EXPECT_EQ(LICENSE_EXPIRED_EVENT, event);

  EXPECT_FALSE(policy_engine_->can_decrypt());
}

TEST_F(PolicyEngineTest, PlaybackFailed_RepeatedRenewFailures) {
  EXPECT_CALL(*mock_clock_, GetCurrentTime())
      .WillOnce(Return(license_start_time_ + 1))
      .WillOnce(Return(license_start_time_ + license_duration_ -
          playback_duration_ + 1))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ - 10))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ + 10))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ + 20))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ + 40))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ + 50))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ + 70))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ + 80))
      .WillOnce(Return(license_start_time_ + license_duration_ + 15));

  policy_engine_->SetLicense(license_);

  policy_engine_->BeginDecryption();
  EXPECT_TRUE(policy_engine_->can_decrypt());

  bool event_occurred;
  CdmEventType event;
  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_TRUE(event_occurred);
  EXPECT_EQ(LICENSE_RENEWAL_NEEDED_EVENT, event);

  EXPECT_TRUE(policy_engine_->can_decrypt());

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_TRUE(event_occurred);
  EXPECT_EQ(LICENSE_RENEWAL_NEEDED_EVENT, event);

  EXPECT_TRUE(policy_engine_->can_decrypt());

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_TRUE(event_occurred);
  EXPECT_EQ(LICENSE_RENEWAL_NEEDED_EVENT, event);

  EXPECT_TRUE(policy_engine_->can_decrypt());

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_TRUE(event_occurred);
  EXPECT_EQ(LICENSE_EXPIRED_EVENT, event);

  EXPECT_FALSE(policy_engine_->can_decrypt());
}

TEST_F(PolicyEngineTest, PlaybackOk_RenewSuccessAfterExpiry) {
  EXPECT_CALL(*mock_clock_, GetCurrentTime())
      .WillOnce(Return(license_start_time_ + 1))
      .WillOnce(Return(license_start_time_ + license_duration_ -
          playback_duration_ + 1))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ - 10))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ + 10))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ + 20))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ + 40))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ + 50))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ + 70))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ + 80))
      .WillOnce(Return(license_start_time_ + license_duration_ + 10))
      .WillOnce(Return(license_start_time_ + license_duration_ + 30))
      .WillOnce(Return(license_start_time_ + license_duration_ + 40));

  policy_engine_->SetLicense(license_);

  policy_engine_->BeginDecryption();
  EXPECT_TRUE(policy_engine_->can_decrypt());

  bool event_occurred;
  CdmEventType event;
  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_TRUE(event_occurred);
  EXPECT_EQ(LICENSE_RENEWAL_NEEDED_EVENT, event);

  EXPECT_TRUE(policy_engine_->can_decrypt());

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_TRUE(event_occurred);
  EXPECT_EQ(LICENSE_RENEWAL_NEEDED_EVENT, event);

  EXPECT_TRUE(policy_engine_->can_decrypt());

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_TRUE(event_occurred);
  EXPECT_EQ(LICENSE_RENEWAL_NEEDED_EVENT, event);

  EXPECT_TRUE(policy_engine_->can_decrypt());

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_TRUE(event_occurred);
  EXPECT_EQ(LICENSE_EXPIRED_EVENT, event);

  EXPECT_FALSE(policy_engine_->can_decrypt());

  license_.set_license_start_time(license_start_time_ +
                                  license_duration_ + 20);
  LicenseIdentification* id = license_.mutable_id();
  id->set_version(2);
  License_Policy* policy = license_.mutable_policy();
  policy = license_.mutable_policy();
  policy->set_playback_duration_seconds(playback_duration_ + 100);
  policy->set_license_duration_seconds(license_duration_ + 100);

  policy_engine_->UpdateLicense(license_);

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  EXPECT_TRUE(policy_engine_->can_decrypt());
}

TEST_F(PolicyEngineTest, PlaybackOk_RenewSuccessAfterFailures) {
  EXPECT_CALL(*mock_clock_, GetCurrentTime())
      .WillOnce(Return(license_start_time_ + 1))
      .WillOnce(Return(license_start_time_ + license_duration_ -
          playback_duration_ + 1))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ - 10))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ + 10))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ + 20))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ + 40))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ + 50))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ + 55))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ + 67))
      .WillOnce(Return(license_start_time_ + license_renewal_delay_ + 200));

  policy_engine_->SetLicense(license_);

  policy_engine_->BeginDecryption();
  EXPECT_TRUE(policy_engine_->can_decrypt());

  bool event_occurred;
  CdmEventType event;
  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_TRUE(event_occurred);
  EXPECT_EQ(LICENSE_RENEWAL_NEEDED_EVENT, event);

  EXPECT_TRUE(policy_engine_->can_decrypt());

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_TRUE(event_occurred);
  EXPECT_EQ(LICENSE_RENEWAL_NEEDED_EVENT, event);

  EXPECT_TRUE(policy_engine_->can_decrypt());

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  license_.set_license_start_time(license_start_time_ +
                                  license_renewal_delay_ + 55);
  LicenseIdentification* id = license_.mutable_id();
  id->set_version(2);
  policy_engine_->UpdateLicense(license_);

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  EXPECT_TRUE(policy_engine_->can_decrypt());

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  EXPECT_TRUE(policy_engine_->can_decrypt());
}

TEST_F(PolicyEngineTest, PlaybackOk_RenewedWithUsage) {
  EXPECT_CALL(*mock_clock_, GetCurrentTime())
      .WillOnce(Return(license_start_time_ + 1))
      .WillOnce(Return(license_start_time_ + 5))
      .WillOnce(Return(license_start_time_ + 10))
      .WillOnce(Return(license_start_time_ + 20))
      .WillOnce(Return(license_start_time_ + 40))
      .WillOnce(Return(license_start_time_ + 50));

  License_Policy* policy = license_.mutable_policy();
  policy->set_renew_with_usage(true);

  policy_engine_->SetLicense(license_);

  bool event_occurred;
  CdmEventType event;
  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  policy_engine_->BeginDecryption();
  EXPECT_FALSE(policy_engine_->can_decrypt());

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_TRUE(event_occurred);
  EXPECT_EQ(LICENSE_RENEWAL_NEEDED_EVENT, event);

  license_.set_license_start_time(license_start_time_ + 30);
  policy->set_renew_with_usage(false);
  LicenseIdentification* id = license_.mutable_id();
  id->set_version(2);
  policy_engine_->UpdateLicense(license_);

  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  EXPECT_TRUE(policy_engine_->can_decrypt());
}

TEST_F(PolicyEngineTest, QueryFailed_LicenseNotReceived) {
  EXPECT_CALL(*mock_clock_, GetCurrentTime())
      .WillOnce(Return(license_start_time_));

  CdmQueryMap query_info;
  EXPECT_EQ(UNKNOWN_ERROR, policy_engine_->Query(&query_info));
}

TEST_F(PolicyEngineTest, QuerySuccess) {
  EXPECT_CALL(*mock_clock_, GetCurrentTime())
      .WillOnce(Return(license_start_time_ + 1))
      .WillOnce(Return(license_start_time_ + 100));

  License_Policy* policy = license_.mutable_policy();

  policy_engine_->SetLicense(license_);

  CdmQueryMap query_info;
  EXPECT_EQ(NO_ERROR, policy_engine_->Query(&query_info));
  EXPECT_EQ(QUERY_VALUE_STREAMING, query_info[QUERY_KEY_LICENSE_TYPE]);
  EXPECT_EQ(QUERY_VALUE_TRUE, query_info[QUERY_KEY_PLAY_ALLOWED]);
  EXPECT_EQ(QUERY_VALUE_TRUE, query_info[QUERY_KEY_PERSIST_ALLOWED]);
  EXPECT_EQ(QUERY_VALUE_TRUE, query_info[QUERY_KEY_RENEW_ALLOWED]);

  int64_t remaining_time;
  std::istringstream ss;
  ss.str(query_info[QUERY_KEY_LICENSE_DURATION_REMAINING]);
  ss >> remaining_time;
  EXPECT_LT(0, remaining_time);
  ss.str(query_info[QUERY_KEY_PLAYBACK_DURATION_REMAINING]);
  ss >> remaining_time;
  EXPECT_LT(0, remaining_time);

  EXPECT_EQ(query_info[QUERY_KEY_RENEWAL_SERVER_URL],
      policy->renewal_server_url());
}

TEST_F(PolicyEngineTest, QuerySuccess_Offline) {
  EXPECT_CALL(*mock_clock_, GetCurrentTime())
      .WillOnce(Return(license_start_time_ + 5))
      .WillOnce(Return(license_start_time_ + 100));

  LicenseIdentification* id = license_.mutable_id();
  id->set_type(OFFLINE);

  License_Policy* policy = license_.mutable_policy();
  policy->set_can_play(false);
  policy->set_can_persist(false);
  policy->set_can_renew(false);

  policy_engine_->SetLicense(license_);

  bool event_occurred;
  CdmEventType event;
  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  policy_engine_->BeginDecryption();
  EXPECT_FALSE(policy_engine_->can_decrypt());

  CdmQueryMap query_info;
  EXPECT_EQ(NO_ERROR, policy_engine_->Query(&query_info));
  EXPECT_EQ(QUERY_VALUE_OFFLINE, query_info[QUERY_KEY_LICENSE_TYPE]);
  EXPECT_EQ(QUERY_VALUE_FALSE, query_info[QUERY_KEY_PLAY_ALLOWED]);
  EXPECT_EQ(QUERY_VALUE_FALSE, query_info[QUERY_KEY_PERSIST_ALLOWED]);
  EXPECT_EQ(QUERY_VALUE_FALSE, query_info[QUERY_KEY_RENEW_ALLOWED]);

  int64_t remaining_time;
  std::istringstream ss;
  ss.str(query_info[QUERY_KEY_LICENSE_DURATION_REMAINING]);
  ss >> remaining_time;
  EXPECT_EQ(0, remaining_time);
  ss.str(query_info[QUERY_KEY_PLAYBACK_DURATION_REMAINING]);
  ss >> remaining_time;
  EXPECT_EQ(0, remaining_time);

  EXPECT_EQ(query_info[QUERY_KEY_RENEWAL_SERVER_URL],
      policy->renewal_server_url());
}

TEST_F(PolicyEngineTest, QuerySuccess_DurationExpired) {
  EXPECT_CALL(*mock_clock_, GetCurrentTime())
      .WillOnce(Return(license_start_time_ + 1))
      .WillOnce(Return(license_start_time_ + 5))
      .WillOnce(Return(license_start_time_ + 10))
      .WillOnce(Return(license_start_time_ + license_duration_ + 20));

  LicenseIdentification* id = license_.mutable_id();
  id->set_type(OFFLINE);

  License_Policy* policy = license_.mutable_policy();

  policy_engine_->SetLicense(license_);

  bool event_occurred;
  CdmEventType event;
  policy_engine_->OnTimerEvent(event_occurred, event);
  EXPECT_FALSE(event_occurred);

  policy_engine_->BeginDecryption();
  EXPECT_TRUE(policy_engine_->can_decrypt());

  CdmQueryMap query_info;
  EXPECT_EQ(NO_ERROR, policy_engine_->Query(&query_info));
  EXPECT_EQ(QUERY_VALUE_OFFLINE, query_info[QUERY_KEY_LICENSE_TYPE]);
  EXPECT_EQ(QUERY_VALUE_TRUE, query_info[QUERY_KEY_PLAY_ALLOWED]);
  EXPECT_EQ(QUERY_VALUE_TRUE, query_info[QUERY_KEY_PERSIST_ALLOWED]);
  EXPECT_EQ(QUERY_VALUE_TRUE, query_info[QUERY_KEY_RENEW_ALLOWED]);

  int64_t remaining_time;
  std::istringstream ss;
  ss.str(query_info[QUERY_KEY_LICENSE_DURATION_REMAINING]);
  ss >> remaining_time;
  EXPECT_EQ(0, remaining_time);
  ss.str(query_info[QUERY_KEY_PLAYBACK_DURATION_REMAINING]);
  ss >> remaining_time;
  EXPECT_EQ(0, remaining_time);

  EXPECT_EQ(query_info[QUERY_KEY_RENEWAL_SERVER_URL],
      policy->renewal_server_url());
}

}  // wvcdm
