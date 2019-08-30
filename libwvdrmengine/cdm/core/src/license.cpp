// Copyright 2012 Google Inc. All Rights Reserved.

#include "license.h"

#include <vector>

#include "crypto_key.h"
#include "crypto_session.h"
#include "log.h"
#include "policy_engine.h"
#include "properties.h"
#include "privacy_crypto.h"
#include "string_conversions.h"
#include "wv_cdm_constants.h"

namespace {
std::string kCompanyNameKey = "company_name";
std::string kModelNameKey = "model_name";
std::string kArchitectureNameKey = "architecture_name";
std::string kDeviceNameKey = "device_name";
std::string kProductNameKey = "product_name";
std::string kBuildInfoKey = "build_info";
std::string kDeviceIdKey = "device_id";
const unsigned char kServiceCertificateCAPublicKey[] = {
    0x30, 0x82, 0x01, 0x8a, 0x02, 0x82, 0x01, 0x81,
    0x00, 0xb4, 0xfe, 0x39, 0xc3, 0x65, 0x90, 0x03,
    0xdb, 0x3c, 0x11, 0x97, 0x09, 0xe8, 0x68, 0xcd,
    0xf2, 0xc3, 0x5e, 0x9b, 0xf2, 0xe7, 0x4d, 0x23,
    0xb1, 0x10, 0xdb, 0x87, 0x65, 0xdf, 0xdc, 0xfb,
    0x9f, 0x35, 0xa0, 0x57, 0x03, 0x53, 0x4c, 0xf6,
    0x6d, 0x35, 0x7d, 0xa6, 0x78, 0xdb, 0xb3, 0x36,
    0xd2, 0x3f, 0x9c, 0x40, 0xa9, 0x95, 0x26, 0x72,
    0x7f, 0xb8, 0xbe, 0x66, 0xdf, 0xc5, 0x21, 0x98,
    0x78, 0x15, 0x16, 0x68, 0x5d, 0x2f, 0x46, 0x0e,
    0x43, 0xcb, 0x8a, 0x84, 0x39, 0xab, 0xfb, 0xb0,
    0x35, 0x80, 0x22, 0xbe, 0x34, 0x23, 0x8b, 0xab,
    0x53, 0x5b, 0x72, 0xec, 0x4b, 0xb5, 0x48, 0x69,
    0x53, 0x3e, 0x47, 0x5f, 0xfd, 0x09, 0xfd, 0xa7,
    0x76, 0x13, 0x8f, 0x0f, 0x92, 0xd6, 0x4c, 0xdf,
    0xae, 0x76, 0xa9, 0xba, 0xd9, 0x22, 0x10, 0xa9,
    0x9d, 0x71, 0x45, 0xd6, 0xd7, 0xe1, 0x19, 0x25,
    0x85, 0x9c, 0x53, 0x9a, 0x97, 0xeb, 0x84, 0xd7,
    0xcc, 0xa8, 0x88, 0x82, 0x20, 0x70, 0x26, 0x20,
    0xfd, 0x7e, 0x40, 0x50, 0x27, 0xe2, 0x25, 0x93,
    0x6f, 0xbc, 0x3e, 0x72, 0xa0, 0xfa, 0xc1, 0xbd,
    0x29, 0xb4, 0x4d, 0x82, 0x5c, 0xc1, 0xb4, 0xcb,
    0x9c, 0x72, 0x7e, 0xb0, 0xe9, 0x8a, 0x17, 0x3e,
    0x19, 0x63, 0xfc, 0xfd, 0x82, 0x48, 0x2b, 0xb7,
    0xb2, 0x33, 0xb9, 0x7d, 0xec, 0x4b, 0xba, 0x89,
    0x1f, 0x27, 0xb8, 0x9b, 0x88, 0x48, 0x84, 0xaa,
    0x18, 0x92, 0x0e, 0x65, 0xf5, 0xc8, 0x6c, 0x11,
    0xff, 0x6b, 0x36, 0xe4, 0x74, 0x34, 0xca, 0x8c,
    0x33, 0xb1, 0xf9, 0xb8, 0x8e, 0xb4, 0xe6, 0x12,
    0xe0, 0x02, 0x98, 0x79, 0x52, 0x5e, 0x45, 0x33,
    0xff, 0x11, 0xdc, 0xeb, 0xc3, 0x53, 0xba, 0x7c,
    0x60, 0x1a, 0x11, 0x3d, 0x00, 0xfb, 0xd2, 0xb7,
    0xaa, 0x30, 0xfa, 0x4f, 0x5e, 0x48, 0x77, 0x5b,
    0x17, 0xdc, 0x75, 0xef, 0x6f, 0xd2, 0x19, 0x6d,
    0xdc, 0xbe, 0x7f, 0xb0, 0x78, 0x8f, 0xdc, 0x82,
    0x60, 0x4c, 0xbf, 0xe4, 0x29, 0x06, 0x5e, 0x69,
    0x8c, 0x39, 0x13, 0xad, 0x14, 0x25, 0xed, 0x19,
    0xb2, 0xf2, 0x9f, 0x01, 0x82, 0x0d, 0x56, 0x44,
    0x88, 0xc8, 0x35, 0xec, 0x1f, 0x11, 0xb3, 0x24,
    0xe0, 0x59, 0x0d, 0x37, 0xe4, 0x47, 0x3c, 0xea,
    0x4b, 0x7f, 0x97, 0x31, 0x1c, 0x81, 0x7c, 0x94,
    0x8a, 0x4c, 0x7d, 0x68, 0x15, 0x84, 0xff, 0xa5,
    0x08, 0xfd, 0x18, 0xe7, 0xe7, 0x2b, 0xe4, 0x47,
    0x27, 0x12, 0x11, 0xb8, 0x23, 0xec, 0x58, 0x93,
    0x3c, 0xac, 0x12, 0xd2, 0x88, 0x6d, 0x41, 0x3d,
    0xc5, 0xfe, 0x1c, 0xdc, 0xb9, 0xf8, 0xd4, 0x51,
    0x3e, 0x07, 0xe5, 0x03, 0x6f, 0xa7, 0x12, 0xe8,
    0x12, 0xf7, 0xb5, 0xce, 0xa6, 0x96, 0x55, 0x3f,
    0x78, 0xb4, 0x64, 0x82, 0x50, 0xd2, 0x33, 0x5f,
    0x91, 0x02, 0x03, 0x01, 0x00, 0x01};
}

namespace wvcdm {

// Protobuf generated classes.
using video_widevine_server::sdk::ClientIdentification;
using video_widevine_server::sdk::ClientIdentification_NameValue;
using video_widevine_server::sdk::DeviceCertificate;
using video_widevine_server::sdk::EncryptedClientIdentification;
using video_widevine_server::sdk::LicenseRequest;
using video_widevine_server::sdk::LicenseRequest_ContentIdentification;
using video_widevine_server::sdk::LicenseRequest_ContentIdentification_CENC;
using video_widevine_server::sdk::
    LicenseRequest_ContentIdentification_ExistingLicense;
using video_widevine_server::sdk::License;
using video_widevine_server::sdk::License_KeyContainer;
using video_widevine_server::sdk::LicenseError;
using video_widevine_server::sdk::SignedDeviceCertificate;
using video_widevine_server::sdk::SignedMessage;

static std::vector<CryptoKey> ExtractContentKeys(const License& license) {
  std::vector<CryptoKey> key_array;

  // Extract content key(s)
  for (int i = 0; i < license.key_size(); ++i) {
    CryptoKey key;
    size_t length;
    switch (license.key(i).type()) {
      case License_KeyContainer::CONTENT:
      case License_KeyContainer::OPERATOR_SESSION:
        key.set_key_id(license.key(i).id());
        // Strip off PKCS#5 padding - since we know the key is 16 or 32 bytes,
        // the padding will always be 16 bytes.
        if (license.key(i).key().size() > 16) {
          length = license.key(i).key().size() - 16;
        } else {
          length = 0;
        }
        key.set_key_data(license.key(i).key().substr(0, length));
        key.set_key_data_iv(license.key(i).iv());
        if (license.key(i).has_key_control()) {
          key.set_key_control(license.key(i).key_control().key_control_block());
          key.set_key_control_iv(license.key(i).key_control().iv());
        }
        key_array.push_back(key);
        break;
      case License_KeyContainer::KEY_CONTROL:
        if (license.key(i).has_key_control()) {
          key.set_key_control(license.key(i).key_control().key_control_block());
          if (license.key(i).key_control().has_iv()) {
            key.set_key_control_iv(license.key(i).key_control().iv());
          }
          key_array.push_back(key);
        }
        break;
      default:
        // Ignore SIGNING key types as they are not content related
        break;
    }
  }

  return key_array;
}

bool CdmLicense::Init(const std::string& token, CryptoSession* session,
                      PolicyEngine* policy_engine) {
  if (token.size() == 0) {
    LOGE("CdmLicense::Init: empty token provided");
    return false;
  }
  if (session == NULL || !session->IsOpen()) {
    LOGE("CdmLicense::Init: crypto session not provided or not open");
    return false;
  }
  if (policy_engine == NULL) {
    LOGE("CdmLicense::Init: no policy engine provided");
    return false;
  }
  token_ = token;
  session_ = session;
  policy_engine_ = policy_engine;
  initialized_ = true;
  return true;
}

bool CdmLicense::PrepareKeyRequest(const CdmInitData& init_data,
                                   const CdmLicenseType license_type,
                                   const CdmAppParameterMap& app_parameters,
                                   const CdmSessionId& session_id,
                                   CdmKeyMessage* signed_request,
                                   std::string* server_url) {
  if (!initialized_) {
    LOGE("CdmLicense::PrepareKeyRequest: not initialized");
    return false;
  }
  if (init_data.empty() && init_data_.empty()) {
    LOGE("CdmLicense::PrepareKeyRequest: empty init data provided");
    return false;
  }
  if (session_id.empty()) {
    LOGE("CdmLicense::PrepareKeyRequest: empty session id provided");
    return false;
  }
  if (!signed_request) {
    LOGE("CdmLicense::PrepareKeyRequest: no signed request provided");
    return false;
  }
  if (!server_url) {
    LOGE("CdmLicense::PrepareKeyRequest: no server url provided");
    return false;
  }

  bool privacy_mode_enabled = Properties::UsePrivacyMode(session_id);
  std::vector<uint8_t> cert = Properties::GetServiceCertificate(session_id);
  std::string serialized_service_certificate(cert.begin(), cert.end());

  if (serialized_service_certificate.empty())
    serialized_service_certificate = service_certificate_;

  if (privacy_mode_enabled && serialized_service_certificate.empty()) {
    init_data_ = init_data;
    return PrepareServiceCertificateRequest(signed_request, server_url);
  }

  // TODO(gmorgan): Request ID owned by session?
  std::string request_id;
  session_->GenerateRequestId(request_id);

  LicenseRequest license_request;
  ClientIdentification* client_id = license_request.mutable_client_id();

  if (Properties::use_certificates_as_identification())
    client_id->set_type(ClientIdentification::DEVICE_CERTIFICATE);
  else
    client_id->set_type(ClientIdentification::KEYBOX);
  client_id->set_token(token_);

  ClientIdentification_NameValue* client_info;
  CdmAppParameterMap::const_iterator iter;
  for (iter = app_parameters.begin(); iter != app_parameters.end(); iter++) {
    client_info = client_id->add_client_info();
    client_info->set_name(iter->first);
    client_info->set_value(iter->second);
  }
  std::string value;
  if (Properties::GetCompanyName(&value)) {
    client_info = client_id->add_client_info();
    client_info->set_name(kCompanyNameKey);
    client_info->set_value(value);
  }
  if (Properties::GetModelName(&value)) {
    client_info = client_id->add_client_info();
    client_info->set_name(kModelNameKey);
    client_info->set_value(value);
  }
  if (Properties::GetArchitectureName(&value)) {
    client_info = client_id->add_client_info();
    client_info->set_name(kArchitectureNameKey);
    client_info->set_value(value);
  }
  if (Properties::GetDeviceName(&value)) {
    client_info = client_id->add_client_info();
    client_info->set_name(kDeviceNameKey);
    client_info->set_value(value);
  }
  if (Properties::GetProductName(&value)) {
    client_info = client_id->add_client_info();
    client_info->set_name(kProductNameKey);
    client_info->set_value(value);
  }
  if (Properties::GetBuildInfo(&value)) {
    client_info = client_id->add_client_info();
    client_info->set_name(kBuildInfoKey);
    client_info->set_value(value);
  }

  if (session_->GetDeviceUniqueId(&value)) {
    client_info = client_id->add_client_info();
    client_info->set_name(kDeviceIdKey);
    client_info->set_value(value);
  }

  if (privacy_mode_enabled) {
    EncryptedClientIdentification* encrypted_client_id =
        license_request.mutable_encrypted_client_id();
    DeviceCertificate service_certificate;

    if (!service_certificate.ParseFromString(serialized_service_certificate)) {
      LOGE(
          "CdmLicense::PrepareKeyRequest: unable to parse retrieved "
          "service certificate");
      return false;
    }

    if (service_certificate.type() !=
        video_widevine_server::sdk::DeviceCertificate_CertificateType_SERVICE) {
      LOGE(
          "CdmLicense::PrepareKeyRequest: retrieved certificate not of type"
          " service, %d",
          service_certificate.type());
      return false;
    }
    encrypted_client_id->set_service_id(service_certificate.service_id());
    encrypted_client_id->set_service_certificate_serial_number(
        service_certificate.serial_number());

    std::string iv(KEY_IV_SIZE, 0);
    std::string key(KEY_SIZE, 0);

    if (!session_->GetRandom(key.size(), reinterpret_cast<uint8_t*>(&key[0]))) {
      return false;
    }
    if (!session_->GetRandom(iv.size(), reinterpret_cast<uint8_t*>(&iv[0]))) {
      return false;
    }
    std::string id, enc_id, enc_key;
    client_id->SerializeToString(&id);

    AesCbcKey aes;
    if (!aes.Init(key)) return false;
    if (!aes.Encrypt(id, &enc_id, &iv)) return false;

    RsaPublicKey rsa;
    if (!rsa.Init(service_certificate.public_key())) return false;
    if (!rsa.Encrypt(key, &enc_key)) return false;

    encrypted_client_id->set_encrypted_client_id_iv(iv);
    encrypted_client_id->set_encrypted_privacy_key(enc_key);
    encrypted_client_id->set_encrypted_client_id(enc_id);
    license_request.clear_client_id();
  }

  // Content Identification may be a cenc_id, a webm_id or a license_id
  LicenseRequest_ContentIdentification* content_id =
      license_request.mutable_content_id();

  LicenseRequest_ContentIdentification_CENC* cenc_content_id =
      content_id->mutable_cenc_id();

  if (!init_data.empty()) {
    cenc_content_id->add_pssh(init_data);
  } else if (privacy_mode_enabled && !init_data_.empty()) {
    cenc_content_id->add_pssh(init_data_);
  } else {
    LOGD("CdmLicense::PrepareKeyRequest: init data not available");
    return false;
  }

  switch (license_type) {
    case kLicenseTypeOffline:
      cenc_content_id->set_license_type(video_widevine_server::sdk::OFFLINE);
      break;
    case kLicenseTypeStreaming:
      cenc_content_id->set_license_type(video_widevine_server::sdk::STREAMING);
      break;
    default:
      LOGD("CdmLicense::PrepareKeyRequest: Unknown license type = %d",
           license_type);
      return false;
      break;
  }
  cenc_content_id->set_request_id(request_id);

  // TODO(jfore): The time field will be updated once the cdm wrapper
  // has been updated to pass us in the time.
  license_request.set_request_time(0);

  license_request.set_type(LicenseRequest::NEW);

  // Get/set the nonce.  This value will be reflected in the Key Control Block
  // of the license response.
  uint32_t nonce;
  if (!session_->GenerateNonce(&nonce)) {
    return false;
  }
  license_request.set_key_control_nonce(nonce);
  LOGD("PrepareKeyRequest: nonce=%u", nonce);
  license_request.set_protocol_version(video_widevine_server::sdk::VERSION_2_1);

  // License request is complete. Serialize it.
  std::string serialized_license_req;
  license_request.SerializeToString(&serialized_license_req);

  if (Properties::use_certificates_as_identification())
    key_request_ = serialized_license_req;

  // Derive signing and encryption keys and construct signature.
  std::string license_request_signature;
  if (!session_->PrepareRequest(serialized_license_req, false,
                                &license_request_signature)) {
    signed_request->clear();
    return false;
  }

  if (license_request_signature.empty()) {
    LOGE("CdmLicense::PrepareKeyRequest: License request signature empty");
    signed_request->clear();
    return false;
  }

  // Put serialize license request and signature together
  SignedMessage signed_message;
  signed_message.set_type(SignedMessage::LICENSE_REQUEST);
  signed_message.set_signature(license_request_signature);
  signed_message.set_msg(serialized_license_req);

  signed_message.SerializeToString(signed_request);

  *server_url = server_url_;
  return true;
}

bool CdmLicense::PrepareKeyUpdateRequest(bool is_renewal,
                                         CdmKeyMessage* signed_request,
                                         std::string* server_url) {
  if (!initialized_) {
    LOGE("CdmLicense::PrepareKeyUpdateRequest: not initialized");
    return false;
  }
  if (!signed_request) {
    LOGE("CdmLicense::PrepareKeyUpdateRequest: No signed request provided");
    return false;
  }
  if (!server_url) {
    LOGE("CdmLicense::PrepareKeyUpdateRequest: No server url provided");
    return false;
  }

  LicenseRequest license_request;
  if (is_renewal)
    license_request.set_type(LicenseRequest::RENEWAL);
  else
    license_request.set_type(LicenseRequest::RELEASE);

  LicenseRequest_ContentIdentification_ExistingLicense* current_license =
      license_request.mutable_content_id()->mutable_license();
  current_license->mutable_license_id()->CopyFrom(policy_engine_->license_id());

  // Get/set the nonce.  This value will be reflected in the Key Control Block
  // of the license response.
  uint32_t nonce;
  if (!session_->GenerateNonce(&nonce)) {
    return false;
  }
  license_request.set_key_control_nonce(nonce);
  LOGD("PrepareKeyUpdateRequest: nonce=%u", nonce);
  license_request.set_protocol_version(video_widevine_server::sdk::VERSION_2_1);

  // License request is complete. Serialize it.
  std::string serialized_license_req;
  license_request.SerializeToString(&serialized_license_req);

  // Construct signature.
  std::string license_request_signature;
  if (!session_->PrepareRenewalRequest(serialized_license_req,
                                       &license_request_signature))
    return false;

  if (license_request_signature.empty()) {
    LOGE(
        "CdmLicense::PrepareKeyUpdateRequest: empty license request"
        " signature");
    return false;
  }

  // Put serialize license request and signature together
  SignedMessage signed_message;
  signed_message.set_type(SignedMessage::LICENSE_REQUEST);
  signed_message.set_signature(license_request_signature);
  signed_message.set_msg(serialized_license_req);

  signed_message.SerializeToString(signed_request);
  *server_url = server_url_;
  return true;
}

CdmResponseType CdmLicense::HandleKeyResponse(
    const CdmKeyResponse& license_response) {
  if (!initialized_) {
    LOGE("CdmLicense::HandleKeyResponse: not initialized");
    return KEY_ERROR;
  }
  if (license_response.empty()) {
    LOGE("CdmLicense::HandleKeyResponse: empty license response");
    return KEY_ERROR;
  }

  SignedMessage signed_response;
  if (!signed_response.ParseFromString(license_response)) {
    LOGE(
        "CdmLicense::HandleKeyResponse: unable to parse signed license"
        " response");
    return KEY_ERROR;
  }

  switch (signed_response.type()) {
    case SignedMessage::LICENSE:
      break;
    case SignedMessage::SERVICE_CERTIFICATE:
      return CdmLicense::HandleServiceCertificateResponse(signed_response);
    case SignedMessage::ERROR:
      return HandleKeyErrorResponse(signed_response);
    default:
      LOGE("CdmLicense::HandleKeyResponse: unrecognized signed message type: %d"
           , signed_response.type());
      return KEY_ERROR;
  }

  if (!signed_response.has_signature()) {
    LOGE("CdmLicense::HandleKeyResponse: license response is not signed");
    return KEY_ERROR;
  }

  License license;
  if (!license.ParseFromString(signed_response.msg())) {
    LOGE("CdmLicense::HandleKeyResponse: unable to parse license response");
    return KEY_ERROR;
  }

  if (Properties::use_certificates_as_identification()) {
    if (!signed_response.has_session_key()) {
      LOGE("CdmLicense::HandleKeyResponse: no session keys present");
      return KEY_ERROR;
    }

    if (!session_->GenerateDerivedKeys(key_request_,
                                       signed_response.session_key()))
      return KEY_ERROR;
  }

  // Extract mac key
  std::string mac_key_iv;
  std::string mac_key;
  if (license.policy().can_renew()) {
    for (int i = 0; i < license.key_size(); ++i) {
      if (license.key(i).type() == License_KeyContainer::SIGNING) {
        mac_key_iv.assign(license.key(i).iv());

        // Strip off PKCS#5 padding
        mac_key.assign(license.key(i).key().data(), MAC_KEY_SIZE);
      }
    }

    if (mac_key_iv.size() != KEY_IV_SIZE || mac_key.size() != MAC_KEY_SIZE) {
      LOGE(
          "CdmLicense::HandleKeyResponse: mac key/iv size error"
          "(key/iv size expected: %d/%d, actual: %d/%d",
          MAC_KEY_SIZE, KEY_IV_SIZE, mac_key.size(), mac_key_iv.size());
      return KEY_ERROR;
    }
  }

  std::vector<CryptoKey> key_array = ExtractContentKeys(license);
  if (!key_array.size()) {
    LOGE("CdmLicense::HandleKeyResponse : No content keys.");
    return KEY_ERROR;
  }

  if (license.policy().has_renewal_server_url()) {
    server_url_ = license.policy().renewal_server_url();
  }

  // TODO(kqyang, jfore, gmorgan): change SetLicense function signature to
  // be able to return true/false to accept/reject the license. (Pending code
  // merge from Eureka)
  policy_engine_->SetLicense(license);

  CdmResponseType resp = session_->LoadKeys(signed_response.msg(),
                                            signed_response.signature(),
                                            mac_key_iv,
                                            mac_key,
                                            key_array.size(),
                                            &key_array[0]);

  if (KEY_ADDED == resp) {
    loaded_keys_.clear();
    for (std::vector<CryptoKey>::iterator it = key_array.begin();
         it != key_array.end();
         ++it) {
      loaded_keys_.insert(it->key_id());
    }
  }
  return resp;
}

CdmResponseType CdmLicense::HandleKeyUpdateResponse(
    bool is_renewal, const CdmKeyResponse& license_response) {
  if (!initialized_) {
    LOGE("CdmLicense::HandleKeyUpdateResponse: not initialized");
    return KEY_ERROR;
  }
  if (license_response.empty()) {
    LOGE("CdmLicense::HandleKeyUpdateResponse : Empty license response.");
    return KEY_ERROR;
  }

  SignedMessage signed_response;
  if (!signed_response.ParseFromString(license_response)) {
    LOGE("CdmLicense::HandleKeyUpdateResponse: Unable to parse signed message");
    return KEY_ERROR;
  }

  if (signed_response.type() == SignedMessage::ERROR) {
    return HandleKeyErrorResponse(signed_response);
  }

  if (!signed_response.has_signature()) {
    LOGE("CdmLicense::HandleKeyUpdateResponse: signature missing");
    return KEY_ERROR;
  }

  License license;
  if (!license.ParseFromString(signed_response.msg())) {
    LOGE(
        "CdmLicense::HandleKeyUpdateResponse: Unable to parse license"
        " from signed message");
    return KEY_ERROR;
  }

  if (!license.has_id()) {
    LOGE("CdmLicense::HandleKeyUpdateResponse: license id not present");
    return KEY_ERROR;
  }

  if (is_renewal) {
    if (license.policy().has_renewal_server_url() &&
        license.policy().renewal_server_url().size() > 0) {
      server_url_ = license.policy().renewal_server_url();
    }
  }

  // TODO(kqyang, jfore, gmorgan): change UpdateLicense function signature to
  // be able to return true/false to accept/reject the license. (Pending code
  // merge from Eureka)
  policy_engine_->UpdateLicense(license);

  if (!is_renewal) return KEY_ADDED;

  std::vector<CryptoKey> key_array = ExtractContentKeys(license);

  if (session_->RefreshKeys(signed_response.msg(), signed_response.signature(),
                            key_array.size(), &key_array[0])) {
    return KEY_ADDED;
  } else {
    return KEY_ERROR;
  }
}

bool CdmLicense::RestoreOfflineLicense(
    CdmKeyMessage& license_request, CdmKeyResponse& license_response,
    CdmKeyResponse& license_renewal_response) {

  if (license_request.empty() || license_response.empty()) {
    LOGE(
        "CdmLicense::RestoreOfflineLicense: key_request or response empty: "
        "%u %u",
        license_request.size(), license_response.size());
    return false;
  }

  SignedMessage signed_request;
  if (!signed_request.ParseFromString(license_request)) {
    LOGE("CdmLicense::RestoreOfflineLicense: license_request parse failed");
    return false;
  }

  if (signed_request.type() != SignedMessage::LICENSE_REQUEST) {
    LOGE(
        "CdmLicense::RestoreOfflineLicense: license request type: expected = "
        "%d, actual = %d",
        SignedMessage::LICENSE_REQUEST, signed_request.type());
    return false;
  }

  if (Properties::use_certificates_as_identification()) {
    key_request_ = signed_request.msg();
  } else {
    if (!session_->GenerateDerivedKeys(signed_request.msg())) return false;
  }

  CdmResponseType sts = HandleKeyResponse(license_response);

  if (sts != KEY_ADDED) return false;

  if (!license_renewal_response.empty()) {
    sts = HandleKeyUpdateResponse(true, license_renewal_response);

    if (sts != KEY_ADDED) return false;
  }

  return true;
}

bool CdmLicense::PrepareServiceCertificateRequest(CdmKeyMessage* signed_request,
                                                  std::string* server_url) {
  if (!initialized_) {
    LOGE("CdmLicense::PrepareServiceCertificateRequest: not initialized");
    return false;
  }
  if (!signed_request) {
    LOGE(
        "CdmLicense::PrepareServiceCertificateRequest: no signed request"
        " provided");
    return false;
  }
  if (!server_url) {
    LOGE(
        "CdmLicense::PrepareServiceCertificateRequest: no server url"
        " provided");
    return false;
  }
  SignedMessage signed_message;
  signed_message.set_type(SignedMessage::SERVICE_CERTIFICATE_REQUEST);
  signed_message.SerializeToString(signed_request);
  *server_url = server_url_;

  return true;
}

CdmResponseType CdmLicense::HandleServiceCertificateResponse(
    const video_widevine_server::sdk::SignedMessage& signed_response) {

  SignedDeviceCertificate signed_service_certificate;
  if (!signed_service_certificate.ParseFromString(signed_response.msg())) {
    LOGE(
        "CdmLicense::HandleServiceCertificateResponse: unable to parse"
        "signed device certificate");
    return KEY_ERROR;
  }

  RsaPublicKey root_ca_key;
  std::string ca_public_key(
      &kServiceCertificateCAPublicKey[0],
      &kServiceCertificateCAPublicKey[sizeof(kServiceCertificateCAPublicKey)]);
  if (!root_ca_key.Init(ca_public_key)) {
    LOGE(
        "CdmLicense::HandleServiceCertificateResponse: public key "
        "initialization failed");
    return KEY_ERROR;
  }

  if (!root_ca_key.VerifySignature(
          signed_service_certificate.device_certificate(),
          signed_service_certificate.signature())) {
    LOGE(
        "CdmLicense::HandleServiceCertificateResponse: service "
        "certificate verification failed");
    return KEY_ERROR;
  }

  DeviceCertificate service_certificate;
  if (!service_certificate.ParseFromString(
          signed_service_certificate.device_certificate())) {
    LOGE(
        "CdmLicense::HandleServiceCertificateResponse: unable to parse "
        "retrieved service certificate");
    return KEY_ERROR;
  }

  if (service_certificate.type() !=
      video_widevine_server::sdk::DeviceCertificate_CertificateType_SERVICE) {
    LOGE(
        "CdmLicense::HandleServiceCertificateResponse: certificate not of type"
        " service, %d",
        service_certificate.type());
    return KEY_ERROR;
  }

  service_certificate_ = signed_service_certificate.device_certificate();
  return NEED_KEY;
}

CdmResponseType CdmLicense::HandleKeyErrorResponse(
    const SignedMessage& signed_message) {

  LicenseError license_error;
  if (!license_error.ParseFromString(signed_message.msg())) {
    LOGE("CdmLicense::HandleKeyErrorResponse: Unable to parse license error");
    return KEY_ERROR;
  }

  switch (license_error.error_code()) {
    case LicenseError::INVALID_DEVICE_CERTIFICATE:
      return NEED_PROVISIONING;
    case LicenseError::REVOKED_DEVICE_CERTIFICATE:
      return DEVICE_REVOKED;
    case LicenseError::SERVICE_UNAVAILABLE:
    default:
      LOGW("CdmLicense::HandleKeyErrorResponse: Unknwon error type = %d",
           license_error.error_code());
      return KEY_ERROR;
  }
}

bool CdmLicense::IsKeyLoaded(const KeyId& key_id) {
  return loaded_keys_.find(key_id) != loaded_keys_.end();
}

}  // namespace wvcdm
