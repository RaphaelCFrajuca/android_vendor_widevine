// Copyright 2013 Google Inc. All Rights Reserved.

#include "license_request.h"
#include "log.h"

namespace wvcdm {

static const std::string kTwoBlankLines("\r\n\r\n");

size_t LicenseRequest::FindHeaderEndPosition(
    const std::string& response) const {
  return(response.find(kTwoBlankLines));
}

// This routine parses the license server's response message and
// extracts the drm message from the response header.
void LicenseRequest::GetDrmMessage(const std::string& response,
                                     std::string& drm_msg) {
  if (response.empty()) {
    drm_msg.clear();
    return;
  }

  // Extracts DRM message.
  // Content-Length = GLS line + Header(s) + empty line + drm message;
  // we use the empty line to locate the drm message, and compute
  // the drm message length as below instead of using Content-Length
  size_t header_end_pos = FindHeaderEndPosition(response);
  if (header_end_pos != std::string::npos) {
    header_end_pos += kTwoBlankLines.size(); // points to response body

    drm_msg.clear();
    size_t drm_msg_pos = response.find(kTwoBlankLines, header_end_pos);
    if (drm_msg_pos != std::string::npos) {
      drm_msg_pos += kTwoBlankLines.size();  // points to drm message
    } else {
      // For backward compatibility, no blank line after error code
      drm_msg_pos = response.find("\r\n", header_end_pos);
      if (drm_msg_pos != std::string::npos) {
        drm_msg_pos += 2;  // points to drm message
      }
    }

    if (drm_msg_pos != std::string::npos) {
      drm_msg = response.substr(drm_msg_pos);
    } else {
      // TODO(edwinwong, rfrias): hack to get HTTP message body out for
      // non-Google Play webservers. Need to clean this up. Possibly test
      // for GLS and decide which part is the drm message
      drm_msg = response.substr(header_end_pos);
      LOGE("drm msg not found");
    }
  } else {
    LOGE("response body not found");
  }
}

// Returns heartbeat url in heartbeat_url.
// The heartbeat url is stored as meta data in the response message.
void LicenseRequest::GetHeartbeatUrl(const std::string& response,
                                     std::string& heartbeat_url) {
  if (response.empty()) {
    heartbeat_url.clear();  // TODO: assign default heartbeat url
    return;
  }

  size_t header_end_pos = FindHeaderEndPosition(response);
  if (header_end_pos != std::string::npos) {
    header_end_pos += kTwoBlankLines.size(); // points to response body

    heartbeat_url.clear();
    size_t heartbeat_url_pos = response.find("Heartbeat-Url: ",
                                                   header_end_pos);
    if (heartbeat_url_pos != std::string::npos) {
      heartbeat_url_pos += sizeof("Heartbeat-Url: ");
      heartbeat_url.assign(response.substr(heartbeat_url_pos));
    } else {
      LOGE("heartbeat url not found");
    }
  } else {
    LOGE("response body not found");
  }
}


} // namespace wvcdm
