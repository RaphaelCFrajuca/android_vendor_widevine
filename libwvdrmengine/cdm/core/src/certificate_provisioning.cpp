// Copyright 2013 Google Inc. All Rights Reserved.

#include "certificate_provisioning.h"
#include "device_files.h"
#include "file_store.h"
#include "license_protocol.pb.h"
#include "log.h"
#include "string_conversions.h"

namespace {
const std::string kDefaultProvisioningServerUrl =
  "https://www.googleapis.com/"
  "certificateprovisioning/v1/devicecertificates/create"
  "?key=AIzaSyB-5OLKTx2iU5mko18DfdwK5611JIjbUhE";
}

namespace wvcdm {
// Protobuf generated classes.
using video_widevine_server::sdk::ClientIdentification;
using video_widevine_server::sdk::ProvisioningRequest;
using video_widevine_server::sdk::ProvisioningResponse;
using video_widevine_server::sdk::SignedProvisioningMessage;

/*
 * This function converts SignedProvisioningRequest into base64 string.
 * It then wraps it in JSON format expected by the Apiary frontend.
 * Apiary requires the base64 encoding to replace '+' with minus '-',
 * and '/' with underscore '_'; opposite to stubby's.
 *
 * Returns the JSON formated string in *request. The JSON string will be
 * appended as a query parameter, i.e. signedRequest=<base 64 encoded
 * SignedProvisioningRequest>. All base64 '=' padding chars must be removed.
 *
 * The JSON formated request takes the following format:
 *
 * base64 encoded message
 */
void CertificateProvisioning::ComposeJsonRequestAsQueryString(
    const std::string& message,
    CdmProvisioningRequest* request) {

  // Performs base64 encoding for message
  std::vector<uint8_t> message_vector(message.begin(), message.end());
  std::string message_b64 = Base64SafeEncodeNoPad(message_vector);
  request->assign(message_b64);
}

/*
 * Composes a device provisioning request and output the request in JSON format
 * in *request. It also returns the default url for the provisioning server
 * in *default_url.
 *
 * Returns NO_ERROR for success and UNKNOWN_ERROR if fails.
 */
CdmResponseType CertificateProvisioning::GetProvisioningRequest(
    SecurityLevel requested_security_level,
    CdmProvisioningRequest* request,
    std::string* default_url) {
  default_url->assign(kDefaultProvisioningServerUrl);

  CdmResponseType sts = crypto_session_.Open(requested_security_level);
  if (NO_ERROR != sts) {
    LOGE("GetProvisioningRequest: fails to create a crypto session");
    return sts;
  }

  // Prepares device provisioning request.
  ProvisioningRequest provisioning_request;
  ClientIdentification* client_id = provisioning_request.mutable_client_id();
  client_id->set_type(ClientIdentification::KEYBOX);
  std::string token;
  if (!crypto_session_.GetToken(&token)) {
    LOGE("GetProvisioningRequest: fails to get token");
    return UNKNOWN_ERROR;
  }
  client_id->set_token(token);

  uint32_t nonce;
  if (!crypto_session_.GenerateNonce(&nonce)) {
    LOGE("GetProvisioningRequest: fails to generate a nonce");
    return UNKNOWN_ERROR;
  }

  // The provisioning server does not convert the nonce to uint32_t, it just
  // passes the binary data to the response message.
  std::string the_nonce(reinterpret_cast<char*>(&nonce), sizeof(nonce));
  provisioning_request.set_nonce(the_nonce);

  std::string serialized_message;
  provisioning_request.SerializeToString(&serialized_message);

  // Derives signing and encryption keys and constructs signature.
  std::string request_signature;
  if (!crypto_session_.PrepareRequest(serialized_message, true,
                                       &request_signature)) {
    LOGE("GetProvisioningRequest: fails to prepare request");
    return UNKNOWN_ERROR;
  }
  if (request_signature.empty()) {
    LOGE("GetProvisioningRequest: request signature is empty");
    return UNKNOWN_ERROR;
  }

  SignedProvisioningMessage signed_provisioning_msg;
  signed_provisioning_msg.set_message(serialized_message);
  signed_provisioning_msg.set_signature(request_signature);

  std::string serialized_request;
  signed_provisioning_msg.SerializeToString(&serialized_request);

  // Converts request into JSON string
  ComposeJsonRequestAsQueryString(serialized_request, request);
  return NO_ERROR;
}

/*
 * Parses the input json_str and locates substring using start_substr and
 * end_stubstr. The found base64 substring is then decoded and returns
 * in *result.
 *
 * Returns true for success and false if fails.
 */
bool CertificateProvisioning::ParseJsonResponse(
    const CdmProvisioningResponse& json_str,
    const std::string& start_substr,
    const std::string& end_substr,
    std::string* result) {
  std::string b64_string;
  size_t start = json_str.find(start_substr);
  if (start == json_str.npos) {
    LOGE("ParseJsonResponse: cannot find start substring");
    return false;
  }
  size_t end = json_str.find(end_substr, start + start_substr.length());
  if (end == json_str.npos) {
    LOGE("ParseJsonResponse cannot locate end substring");
    return false;
  }

  size_t b64_string_size = end - start - start_substr.length();
  b64_string.assign(json_str, start + start_substr.length(), b64_string_size);

  // Decodes base64 substring and returns it in *result
  std::vector<uint8_t> result_vector = Base64SafeDecode(b64_string);
  result->assign(result_vector.begin(), result_vector.end());

  return true;
}

/*
 * The response message consists of a device certificate and the device RSA key.
 * The device RSA key is stored in the T.E.E. The device certificate is stored
 * in the device.
 *
 * Returns NO_ERROR for success and UNKNOWN_ERROR if fails.
 */
CdmResponseType CertificateProvisioning::HandleProvisioningResponse(
    CdmProvisioningResponse& response) {

  // Extracts signed response from JSON string, decodes base64 signed response
  const std::string kMessageStart = "\"signedResponse\": \"";
  const std::string kMessageEnd = "\"";
  std::string serialized_signed_response;
  if (!ParseJsonResponse(response, kMessageStart, kMessageEnd,
                         &serialized_signed_response)) {
    LOGE("Fails to extract signed serialized response from JSON response");
    return UNKNOWN_ERROR;
  }

  // Authenticates provisioning response using D1s (server key derived from
  // the provisioing request's input). Validate provisioning response and
  // stores private device RSA key and certificate.
  SignedProvisioningMessage signed_response;
  if (!signed_response.ParseFromString(serialized_signed_response)) {
    LOGE("HandleProvisioningResponse: fails to parse signed response");
    return UNKNOWN_ERROR;
  }

  if (!signed_response.has_signature() || !signed_response.has_message()) {
    LOGE("HandleProvisioningResponse: signature or message not found");
    return UNKNOWN_ERROR;
  }

  const std::string& signed_message = signed_response.message();
  ProvisioningResponse provisioning_response;

  if (!provisioning_response.ParseFromString(signed_message)) {
    LOGE("HandleProvisioningResponse: Fails to parse signed message");
    return UNKNOWN_ERROR;
  }

  if (!provisioning_response.has_device_rsa_key()) {
    LOGE("HandleProvisioningResponse: key not found");
    return UNKNOWN_ERROR;
  }

  const std::string& enc_rsa_key = provisioning_response.device_rsa_key();
  const std::string& nonce = provisioning_response.nonce();
  const std::string& rsa_key_iv = provisioning_response.device_rsa_key_iv();
  const std::string& signature = signed_response.signature();
  std::string wrapped_rsa_key;
  if (!crypto_session_.RewrapDeviceRSAKey(signed_message,
                                          signature,
                                          nonce,
                                          enc_rsa_key,
                                          rsa_key_iv,
                                          &wrapped_rsa_key)){
    LOGE("HandleProvisioningResponse: RewrapDeviceRSAKey fails");
    return UNKNOWN_ERROR;
  }

  crypto_session_.Close();

  const std::string& device_certificate =
      provisioning_response.device_certificate();

  File file;
  DeviceFiles handle;
  if (!handle.Init(&file, crypto_session_.GetSecurityLevel())) {
    LOGE("HandleProvisioningResponse: failed to init DeviceFiles");
    return UNKNOWN_ERROR;
  }
  if (!handle.StoreCertificate(device_certificate, wrapped_rsa_key)) {
    LOGE("HandleProvisioningResponse: failed to save provisioning certificate");
    return UNKNOWN_ERROR;
  }
  handle.DeleteAllLicenses();

  return NO_ERROR;
}

}  // namespace wvcdm
