// Copyright 2013 Google Inc. All Rights Reserved.

#include "policy_engine.h"

#include <algorithm>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "log.h"
#include "properties.h"
#include "string_conversions.h"
#include "clock.h"
#include "wv_cdm_constants.h"

namespace wvcdm {

PolicyEngine::PolicyEngine() {
  Init(new Clock());
}

PolicyEngine::PolicyEngine(Clock* clock) {
  Init(clock);
}

PolicyEngine::~PolicyEngine() {
  if (clock_)
    delete clock_;
}

void PolicyEngine::Init(Clock* clock) {
  license_state_ = kLicenseStateInitial;
  can_decrypt_ = false;
  license_start_time_ = 0;
  license_received_time_ = 0;
  playback_start_time_ = 0;
  next_renewal_time_ = 0;
  policy_max_duration_seconds_ = 0;
  clock_ = clock;
}

void PolicyEngine::OnTimerEvent(bool& event_occured, CdmEventType& event) {
  event_occured = false;
  int64_t current_time = clock_->GetCurrentTime();

  // License expiration trumps all.
  if ((IsLicenseDurationExpired(current_time) ||
      IsPlaybackDurationExpired(current_time)) &&
      license_state_ != kLicenseStateExpired) {
    license_state_ = kLicenseStateExpired;
    can_decrypt_ = false;
    event = LICENSE_EXPIRED_EVENT;
    event_occured = true;
    return;
  }

  bool renewal_needed = false;

  // Test to determine if renewal should be attempted.
  switch (license_state_) {
    case kLicenseStateInitialPendingUsage:
    case kLicenseStateCanPlay: {
      if (IsRenewalDelayExpired(current_time))
        renewal_needed = true;
      break;
    }

    case kLicenseStateNeedRenewal: {
      renewal_needed = true;
      break;
    }

    case kLicenseStateWaitingLicenseUpdate: {
      if (IsRenewalRetryIntervalExpired(current_time))
        renewal_needed = true;
      break;
    }

    case kLicenseStateInitial:
    case kLicenseStateExpired: {
      break;
    }

    default: {
      license_state_ = kLicenseStateExpired;
      can_decrypt_ = false;
      break;
    }
  }

  if (renewal_needed) {
    UpdateRenewalRequest(current_time);
    event = LICENSE_RENEWAL_NEEDED_EVENT;
    event_occured = true;
  }
}

void PolicyEngine::SetLicense(
    const video_widevine_server::sdk::License& license) {
  license_id_.Clear();
  license_id_.CopyFrom(license.id());
  policy_.Clear();
  UpdateLicense(license);
}

void PolicyEngine::UpdateLicense(
    const video_widevine_server::sdk::License& license) {
  if (!license.has_policy())
    return;

  policy_.MergeFrom(license.policy());

  if (!policy_.can_play()) {
    license_state_ = kLicenseStateExpired;
    return;
  }

  // some basic license validation
  if (license_state_ == kLicenseStateInitial) {
    // license start time needs to be present in the initial response
    if (!license.has_license_start_time())
      return;
  }
  else {
    // TODO(edwingwong, rfrias): Check back with Thomas and see if
    // we need to enforce that all duration windows are absent if
    // license_start_time is not present. This is a TBD.

    // if renewal, discard license if version has not been updated
    if (license.id().version() > license_id_.version())
      license_id_.CopyFrom(license.id());
    else
      return;
  }

  // Update time information
  int64_t current_time = clock_->GetCurrentTime();
  // TODO(edwingwong, rfrias): Check back with Thomas and see if
  // we need to enforce that all duration windows are absent if
  // license_start_time is not present. This is a TBD.
  if (license.has_license_start_time())
    license_start_time_ = license.license_start_time();
  license_received_time_ = current_time;
  next_renewal_time_ = current_time +
      policy_.renewal_delay_seconds();

  // Calculate policy_max_duration_seconds_. policy_max_duration_seconds_
  // will be set to the minimum of the following policies :
  // rental_duration_seconds and license_duration_seconds.
  // The value is used to determine when the license expires.
  policy_max_duration_seconds_ = 0;

  if (policy_.has_rental_duration_seconds())
    policy_max_duration_seconds_ = policy_.rental_duration_seconds();

  if ((policy_.license_duration_seconds() > 0) &&
      ((policy_.license_duration_seconds() <
       policy_max_duration_seconds_) ||
       policy_max_duration_seconds_ == 0)) {
    policy_max_duration_seconds_ = policy_.license_duration_seconds();
  }

  if (Properties::begin_license_usage_when_received())
    playback_start_time_ = current_time;

  // Update state
  if (Properties::begin_license_usage_when_received()) {
    if (policy_.renew_with_usage()) {
      license_state_ = kLicenseStateNeedRenewal;
    }
    else {
      license_state_ = kLicenseStateCanPlay;
      can_decrypt_ = true;
    }
  }
  else {
    if (license_state_ == kLicenseStateInitial) {
      license_state_ = kLicenseStateInitialPendingUsage;
    }
    else {
      license_state_ = kLicenseStateCanPlay;
      can_decrypt_ = true;
    }
  }
}

void PolicyEngine::BeginDecryption() {
  if ((playback_start_time_ == 0) &&
      (!Properties::begin_license_usage_when_received())) {
    switch (license_state_) {
      case kLicenseStateInitialPendingUsage:
      case kLicenseStateNeedRenewal:
      case kLicenseStateWaitingLicenseUpdate:
        playback_start_time_ = clock_->GetCurrentTime();

        if (policy_.renew_with_usage()) {
          license_state_ = kLicenseStateNeedRenewal;
        }
        else {
          license_state_ = kLicenseStateCanPlay;
          can_decrypt_ = true;
        }
        break;
      case kLicenseStateCanPlay:
      case kLicenseStateInitial:
      case kLicenseStateExpired:
      default:
        break;
    }
  }
}

CdmResponseType PolicyEngine::Query(CdmQueryMap* key_info) {
  std::stringstream ss;
  int64_t current_time = clock_->GetCurrentTime();

  if (license_state_ == kLicenseStateInitial)
    return UNKNOWN_ERROR;

  (*key_info)[QUERY_KEY_LICENSE_TYPE] =
    license_id_.type() == video_widevine_server::sdk::STREAMING ?
    QUERY_VALUE_STREAMING : QUERY_VALUE_OFFLINE;
  (*key_info)[QUERY_KEY_PLAY_ALLOWED] = policy_.can_play() ?
    QUERY_VALUE_TRUE : QUERY_VALUE_FALSE;
  (*key_info)[QUERY_KEY_PERSIST_ALLOWED] = policy_.can_persist() ?
    QUERY_VALUE_TRUE : QUERY_VALUE_FALSE;
  (*key_info)[QUERY_KEY_RENEW_ALLOWED] = policy_.can_renew() ?
    QUERY_VALUE_TRUE : QUERY_VALUE_FALSE;
  int64_t remaining_time = policy_max_duration_seconds_ +
      license_received_time_ - current_time;
  if (remaining_time < 0)
    remaining_time = 0;
  ss << remaining_time;
  (*key_info)[QUERY_KEY_LICENSE_DURATION_REMAINING] = ss.str();
  remaining_time = policy_.playback_duration_seconds() + playback_start_time_ -
      current_time;
  if (remaining_time < 0)
    remaining_time = 0;
  ss << remaining_time;
  (*key_info)[QUERY_KEY_PLAYBACK_DURATION_REMAINING] = ss.str();
  (*key_info)[QUERY_KEY_RENEWAL_SERVER_URL] = policy_.renewal_server_url();

  return NO_ERROR;
}

void PolicyEngine::UpdateRenewalRequest(int64_t current_time) {
  license_state_ = kLicenseStateWaitingLicenseUpdate;
  next_renewal_time_ = current_time + policy_.renewal_retry_interval_seconds();
}

// For the policy time fields checked in the following methods, a value of 0
// indicates that there is no limit to the duration. These methods
// will always return false if the value is 0.
bool PolicyEngine::IsLicenseDurationExpired(int64_t current_time) {
  return policy_max_duration_seconds_ &&
      license_received_time_ + policy_max_duration_seconds_ <=
      current_time;
}

bool PolicyEngine::IsPlaybackDurationExpired(int64_t current_time) {
  return (policy_.playback_duration_seconds() > 0) &&
      playback_start_time_ &&
      playback_start_time_ + policy_.playback_duration_seconds() <=
      current_time;
}

bool PolicyEngine::IsRenewalDelayExpired(int64_t current_time) {
  return policy_.can_renew() &&
      (policy_.renewal_delay_seconds() > 0) &&
      license_received_time_ + policy_.renewal_delay_seconds() <=
      current_time;
}

// TODO(jfore, edwinwong, rfrias): This field is in flux and currently
// not implemented. Will address after possible updates from Thomas.
bool PolicyEngine::IsRenewalRecoveryDurationExpired(
    int64_t current_time) {
  return (policy_.renewal_recovery_duration_seconds() > 0) &&
      license_received_time_ + policy_.renewal_recovery_duration_seconds() <=
      current_time;
}

bool PolicyEngine::IsRenewalRetryIntervalExpired(
    int64_t current_time) {
  return policy_.can_renew() &&
      (policy_.renewal_retry_interval_seconds() > 0) &&
      next_renewal_time_ <= current_time;
}

}  // wvcdm
