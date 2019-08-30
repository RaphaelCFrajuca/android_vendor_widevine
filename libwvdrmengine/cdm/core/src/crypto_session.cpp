// Copyright 2012 Google Inc. All Rights Reserved.
//
// Crypto - wrapper classes for OEMCrypto interface
//

#include "crypto_session.h"

#include <arpa/inet.h>  // TODO(fredgc): Add ntoh to wv_cdm_utilities.h
#include <iostream>

#include "crypto_key.h"
#include "log.h"
#include "properties.h"
#include "string_conversions.h"
#include "wv_cdm_constants.h"

namespace {
// Encode unsigned integer into a big endian formatted string
std::string EncodeUint32(unsigned int u) {
  std::string s;
  s.append(1, (u >> 24) & 0xFF);
  s.append(1, (u >> 16) & 0xFF);
  s.append(1, (u >> 8) & 0xFF);
  s.append(1, (u >> 0) & 0xFF);
  return s;
}
}

namespace wvcdm {

Lock CryptoSession::crypto_lock_;
bool CryptoSession::initialized_ = false;
int CryptoSession::session_count_ = 0;

CryptoSession::CryptoSession()
    : open_(false),
      is_destination_buffer_type_valid_(false),
      requested_security_level_(kLevelDefault) {
  Init();
}

CryptoSession::~CryptoSession() {
  if (open_) {
    Close();
  }
  Terminate();
}

void CryptoSession::Init() {
  LOGV("CryptoSession::Init");
  AutoLock auto_lock(crypto_lock_);
  session_count_ += 1;
  if (initialized_) return;
  OEMCryptoResult sts = OEMCrypto_Initialize();
  if (OEMCrypto_SUCCESS != sts) {
    LOGE("OEMCrypto_Initialize failed: %d", sts);
    return;
  }
  initialized_ = true;
}

void CryptoSession::Terminate() {
  LOGV("CryptoSession::Terminate");
  AutoLock auto_lock(crypto_lock_);
  session_count_ -= 1;
  if (session_count_ > 0 || !initialized_) return;
  OEMCryptoResult sts = OEMCrypto_Terminate();
  if (OEMCrypto_SUCCESS != sts) {
    LOGE("OEMCrypto_Terminate failed: %d", sts);
  }
  initialized_ = false;
}

bool CryptoSession::ValidateKeybox() {
  LOGV("CryptoSession::ValidateKeybox: Lock");
  AutoLock auto_lock(crypto_lock_);
  if (!initialized_) {
    return false;
  }
  OEMCryptoResult result = OEMCrypto_IsKeyboxValid(requested_security_level_);
  return (OEMCrypto_SUCCESS == result);
}

bool CryptoSession::GetToken(std::string* token) {
  if (!token) {
    LOGE("CryptoSession::GetToken : No token passed to method.");
    return false;
  }
  uint8_t buf[KEYBOX_KEY_DATA_SIZE];
  size_t bufSize = sizeof(buf);
  LOGV("CryptoSession::GetToken: Lock");
  AutoLock auto_lock(crypto_lock_);
  if (!initialized_) {
    return false;
  }
  OEMCryptoResult sts =
      OEMCrypto_GetKeyData(buf, &bufSize, requested_security_level_);
  if (OEMCrypto_SUCCESS != sts) {
    return false;
  }
  token->assign((const char*)buf, (size_t)bufSize);
  return true;
}

CdmSecurityLevel CryptoSession::GetSecurityLevel() {
  LOGV("CryptoSession::GetSecurityLevel: Lock");
  AutoLock auto_lock(crypto_lock_);
  if (!initialized_) {
    return kSecurityLevelUninitialized;
  }

  std::string security_level =
      OEMCrypto_SecurityLevel(requested_security_level_);

  if ((security_level.size() != 2) || (security_level.at(0) != 'L')) {
    return kSecurityLevelUnknown;
  }

  switch (security_level.at(1)) {
    case '1':
      return kSecurityLevelL1;
    case '2':
      return kSecurityLevelL2;
    case '3':
      return kSecurityLevelL3;
    default:
      return kSecurityLevelUnknown;
  }

  return kSecurityLevelUnknown;
}

bool CryptoSession::GetDeviceUniqueId(std::string* device_id) {
  if (!device_id) {
    LOGE("CryptoSession::GetDeviceUniqueId : No buffer passed to method.");
    return false;
  }

  std::vector<uint8_t> id;
  size_t id_length = 32;

  id.resize(id_length);

  LOGV("CryptoSession::GetDeviceUniqueId: Lock");
  AutoLock auto_lock(crypto_lock_);
  if (!initialized_) {
    return false;
  }
  OEMCryptoResult sts =
      OEMCrypto_GetDeviceID(&id[0], &id_length, requested_security_level_);

  if (OEMCrypto_SUCCESS != sts) {
    return false;
  }

  *device_id = reinterpret_cast<const char*>(&id[0]);
  return true;
}

bool CryptoSession::GetSystemId(uint32_t* system_id) {
  if (!system_id) {
    LOGE("CryptoSession::GetSystemId : No buffer passed to method.");
    return false;
  }

  uint8_t buf[KEYBOX_KEY_DATA_SIZE];
  size_t buf_size = sizeof(buf);

  LOGV("CryptoSession::GetSystemId: Lock");
  AutoLock auto_lock(crypto_lock_);
  if (!initialized_) {
    return false;
  }
  OEMCryptoResult sts =
      OEMCrypto_GetKeyData(buf, &buf_size, requested_security_level_);

  if (OEMCrypto_SUCCESS != sts) {
    return false;
  }

  // Decode 32-bit int encoded as network-byte-order byte array starting at
  // index 4.
  uint32_t* id = reinterpret_cast<uint32_t*>(&buf[4]);

  *system_id = ntohl(*id);
  return true;
}

bool CryptoSession::GetProvisioningId(std::string* provisioning_id) {
  if (!provisioning_id) {
    LOGE("CryptoSession::GetProvisioningId : No buffer passed to method.");
    return false;
  }

  uint8_t buf[KEYBOX_KEY_DATA_SIZE];
  size_t buf_size = sizeof(buf);

  LOGV("CryptoSession::GetProvisioningId: Lock");
  AutoLock auto_lock(crypto_lock_);
  if (!initialized_) {
    return false;
  }
  OEMCryptoResult sts =
      OEMCrypto_GetKeyData(buf, &buf_size, requested_security_level_);

  if (OEMCrypto_SUCCESS != sts) {
    return false;
  }

  provisioning_id->assign(reinterpret_cast<char*>(&buf[8]), 16);
  return true;
}

CdmResponseType CryptoSession::Open(SecurityLevel requested_security_level) {
  LOGV("CryptoSession::Open: Lock");
  AutoLock auto_lock(crypto_lock_);
  if (!initialized_) return UNKNOWN_ERROR;
  if (open_) return NO_ERROR;

  OEMCrypto_SESSION sid;
  requested_security_level_ = requested_security_level;
  OEMCryptoResult sts = OEMCrypto_OpenSession(&sid, requested_security_level);
  if (OEMCrypto_SUCCESS == sts) {
    oec_session_id_ = static_cast<CryptoSessionId>(sid);
    LOGV("OpenSession: id= %ld", (uint32_t)oec_session_id_);
    open_ = true;
  } else if (OEMCrypto_ERROR_TOO_MANY_SESSIONS == sts) {
    return INSUFFICIENT_CRYPTO_RESOURCES;
  }
  return open_ ? NO_ERROR : UNKNOWN_ERROR;
}

void CryptoSession::Close() {
  LOGV("CloseSession: id=%ld open=%s", (uint32_t)oec_session_id_,
       open_ ? "true" : "false");
  AutoLock auto_lock(crypto_lock_);
  if (!open_) return;
  if (OEMCrypto_SUCCESS == OEMCrypto_CloseSession(oec_session_id_)) {
    open_ = false;
  }
}

void CryptoSession::GenerateRequestId(std::string& req_id_str) {
  LOGV("CryptoSession::GenerateRequestId: Lock");
  AutoLock auto_lock(crypto_lock_);
  // TODO(gmorgan): Get unique ID from OEMCrypto
  req_id_str.assign("987654321");
}

bool CryptoSession::PrepareRequest(const std::string& message,
                                   bool is_provisioning,
                                   std::string* signature) {
  LOGV("CryptoSession::PrepareRequest: Lock");
  AutoLock auto_lock(crypto_lock_);

  if (!signature) {
    LOGE("CryptoSession::PrepareRequest : No output destination provided.");
    return false;
  }

  if (!Properties::use_certificates_as_identification() || is_provisioning) {
    if (!GenerateDerivedKeys(message)) return false;

    if (!GenerateSignature(message, false, signature)) return false;
  } else {
    if (!GenerateSignature(message, true, signature)) return false;
  }

  return true;
}

bool CryptoSession::PrepareRenewalRequest(const std::string& message,
                                          std::string* signature) {
  LOGV("CryptoSession::PrepareRenewalRequest: Lock");
  AutoLock auto_lock(crypto_lock_);

  if (!signature) {
    LOGE("CryptoSession::PrepareRenewalRequest : No output destination "
         "provided.");
    return false;
  }

  if (!GenerateSignature(message, false, signature)) {
    return false;
  }

  return true;
}

void CryptoSession::GenerateMacContext(const std::string& input_context,
                                       std::string* deriv_context) {
  if (!deriv_context) {
    LOGE("CryptoSession::GenerateMacContext : No output destination provided.");
    return;
  }

  const std::string kSigningKeyLabel = "AUTHENTICATION";
  const size_t kSigningKeySizeBits = MAC_KEY_SIZE * 8;

  deriv_context->assign(kSigningKeyLabel);
  deriv_context->append(1, '\0');
  deriv_context->append(input_context);
  deriv_context->append(EncodeUint32(kSigningKeySizeBits * 2));
}

void CryptoSession::GenerateEncryptContext(const std::string& input_context,
                                           std::string* deriv_context) {
  if (!deriv_context) {
    LOGE("CryptoSession::GenerateEncryptContext : No output destination "
         "provided.");
    return;
  }

  const std::string kEncryptionKeyLabel = "ENCRYPTION";
  const size_t kEncryptionKeySizeBits = KEY_SIZE * 8;

  deriv_context->assign(kEncryptionKeyLabel);
  deriv_context->append(1, '\0');
  deriv_context->append(input_context);
  deriv_context->append(EncodeUint32(kEncryptionKeySizeBits));
}

size_t CryptoSession::GetOffset(std::string message, std::string field) {
  size_t pos = message.find(field);
  if (pos == std::string::npos) {
    LOGE("CryptoSession::GetOffset : Cannot find offset for %s", field.c_str());
    pos = 0;
  }
  return pos;
}

CdmResponseType CryptoSession::LoadKeys(const std::string& message,
                                        const std::string& signature,
                                        const std::string& mac_key_iv,
                                        const std::string& mac_key,
                                        int num_keys,
                                        const CryptoKey* key_array) {
  LOGV("CryptoSession::LoadKeys: Lock");
  AutoLock auto_lock(crypto_lock_);

  const uint8_t* msg = reinterpret_cast<const uint8_t*>(message.data());
  const uint8_t* enc_mac_key = NULL;
  const uint8_t* enc_mac_key_iv = NULL;
  if (mac_key.size() >= MAC_KEY_SIZE && mac_key_iv.size() >= KEY_IV_SIZE) {
    enc_mac_key = msg + GetOffset(message, mac_key);
    enc_mac_key_iv = msg + GetOffset(message, mac_key_iv);
  }
  std::vector<OEMCrypto_KeyObject> load_key_array(num_keys);
  for (int i = 0; i < num_keys; ++i) {
    const CryptoKey* ki = &key_array[i];
    OEMCrypto_KeyObject* ko = &load_key_array[i];
    ko->key_id = msg + GetOffset(message, ki->key_id());
    ko->key_id_length = ki->key_id().length();
    ko->key_data_iv = msg + GetOffset(message, ki->key_data_iv());
    ko->key_data = msg + GetOffset(message, ki->key_data());
    ko->key_data_length = ki->key_data().length();
    if (ki->HasKeyControl()) {
      ko->key_control_iv = msg + GetOffset(message, ki->key_control_iv());
      ko->key_control = msg + GetOffset(message, ki->key_control());
    } else {
      LOGE("For key %d: XXX key has no control block. size=%d", i,
           ki->key_control().size());
      ko->key_control_iv = NULL;
      ko->key_control = NULL;
    }
  }
  LOGV("LoadKeys: id=%ld", (uint32_t)oec_session_id_);
  OEMCryptoResult sts = OEMCrypto_LoadKeys(
      oec_session_id_, msg, message.size(),
      reinterpret_cast<const uint8_t*>(signature.data()), signature.size(),
      enc_mac_key_iv, enc_mac_key, num_keys, &load_key_array[0]);

  if (OEMCrypto_SUCCESS == sts) {
    return KEY_ADDED;
  } else if (OEMCrypto_ERROR_TOO_MANY_KEYS == sts) {
    return INSUFFICIENT_CRYPTO_RESOURCES;
  } else {
    return KEY_ERROR;
  }
}

bool CryptoSession::LoadCertificatePrivateKey(std::string& wrapped_key) {
  LOGV("CryptoSession::LoadKeys: Lock");
  AutoLock auto_lock(crypto_lock_);

  LOGV("LoadDeviceRSAKey: id=%ld", (uint32_t)oec_session_id_);
  OEMCryptoResult sts = OEMCrypto_LoadDeviceRSAKey(
      oec_session_id_, reinterpret_cast<const uint8_t*>(wrapped_key.data()),
      wrapped_key.size());

  if (OEMCrypto_SUCCESS != sts) {
    LOGD("LoadCertificatePrivateKey: OEMCrypto_LoadDeviceRSAKey error=%d", sts);
    return false;
  }

  return true;
}

bool CryptoSession::RefreshKeys(const std::string& message,
                                const std::string& signature, int num_keys,
                                const CryptoKey* key_array) {
  LOGV("CryptoSession::RefreshKeys: Lock");
  AutoLock auto_lock(crypto_lock_);

  const uint8_t* msg = reinterpret_cast<const uint8_t*>(message.data());
  std::vector<OEMCrypto_KeyRefreshObject> load_key_array(num_keys);
  for (int i = 0; i < num_keys; ++i) {
    const CryptoKey* ki = &key_array[i];
    OEMCrypto_KeyRefreshObject* ko = &load_key_array[i];
    if (ki->key_id().empty()) {
      ko->key_id = NULL;
    } else {
      ko->key_id = msg + GetOffset(message, ki->key_id());
    }
    if (ki->HasKeyControl()) {
      if (ki->key_control_iv().empty()) {
        ko->key_control_iv = NULL;
      } else {
        ko->key_control_iv = msg + GetOffset(message, ki->key_control_iv());
      }
      ko->key_control = msg + GetOffset(message, ki->key_control());
    } else {
      ko->key_control_iv = NULL;
      ko->key_control = NULL;
    }
  }
  LOGV("RefreshKeys: id=%ld", static_cast<uint32_t>(oec_session_id_));
  return (
      OEMCrypto_SUCCESS ==
      OEMCrypto_RefreshKeys(oec_session_id_, msg, message.size(),
                            reinterpret_cast<const uint8_t*>(signature.data()),
                            signature.size(), num_keys, &load_key_array[0]));
}

bool CryptoSession::SelectKey(const std::string& key_id) {
  const uint8_t* key_id_string =
      reinterpret_cast<const uint8_t*>(key_id.data());

  OEMCryptoResult sts =
      OEMCrypto_SelectKey(oec_session_id_, key_id_string, key_id.size());
  if (OEMCrypto_SUCCESS != sts) {
    return false;
  }
  return true;
}

bool CryptoSession::GenerateDerivedKeys(const std::string& message) {
  std::string mac_deriv_message;
  std::string enc_deriv_message;
  GenerateMacContext(message, &mac_deriv_message);
  GenerateEncryptContext(message, &enc_deriv_message);

  LOGV("GenerateDerivedKeys: id=%ld", (uint32_t)oec_session_id_);
  OEMCryptoResult sts = OEMCrypto_GenerateDerivedKeys(
      oec_session_id_,
      reinterpret_cast<const uint8_t*>(mac_deriv_message.data()),
      mac_deriv_message.size(),
      reinterpret_cast<const uint8_t*>(enc_deriv_message.data()),
      enc_deriv_message.size());

  if (OEMCrypto_SUCCESS != sts) {
    LOGD("GenerateDerivedKeys: OEMCrypto_GenerateDerivedKeys error=%d", sts);
    return false;
  }

  return true;
}

bool CryptoSession::GenerateDerivedKeys(const std::string& message,
                                        const std::string& session_key) {
  std::string mac_deriv_message;
  std::string enc_deriv_message;
  GenerateMacContext(message, &mac_deriv_message);
  GenerateEncryptContext(message, &enc_deriv_message);

  LOGV("GenerateDerivedKeys: id=%ld", (uint32_t)oec_session_id_);
  OEMCryptoResult sts = OEMCrypto_DeriveKeysFromSessionKey(
      oec_session_id_, reinterpret_cast<const uint8_t*>(session_key.data()),
      session_key.size(),
      reinterpret_cast<const uint8_t*>(mac_deriv_message.data()),
      mac_deriv_message.size(),
      reinterpret_cast<const uint8_t*>(enc_deriv_message.data()),
      enc_deriv_message.size());

  if (OEMCrypto_SUCCESS != sts) {
    LOGD("GenerateDerivedKeys: OEMCrypto_DeriveKeysFromSessionKey err=%d", sts);
    return false;
  }

  return true;
}

bool CryptoSession::GenerateSignature(const std::string& message, bool use_rsa,
                                      std::string* signature) {
  LOGV("GenerateSignature: id=%ld", (uint32_t)oec_session_id_);
  if (!signature) return false;

  size_t length = 0;
  OEMCryptoResult sts = OEMCrypto_SUCCESS;
  if (use_rsa) {
    sts = OEMCrypto_GenerateRSASignature(
        oec_session_id_, reinterpret_cast<const uint8_t*>(message.data()),
        message.size(), NULL, &length);
    if (OEMCrypto_ERROR_SHORT_BUFFER != sts) {
      LOGD("GenerateSignature: OEMCrypto_GenerateRSASignature err=%d", sts);
      return false;
    }
  } else {
    length = kSignatureSize;
    // TODO(gmorgan,kqyang): Use OEMCrypto_GenerateSignature to determine
    // length after marvell fixes their implementation.
    /*
    sts = OEMCrypto_GenerateSignature(
        oec_session_id_, reinterpret_cast<const uint8_t*>(message.data()),
        message.size(), NULL, &length);
    */
  }

  signature->resize(length);

  if (use_rsa) {
    sts = OEMCrypto_GenerateRSASignature(
        oec_session_id_, reinterpret_cast<const uint8_t*>(message.data()),
        message.size(),
        reinterpret_cast<uint8_t*>(const_cast<char*>(signature->data())),
        &length);
  } else {
    sts = OEMCrypto_GenerateSignature(
        oec_session_id_, reinterpret_cast<const uint8_t*>(message.data()),
        message.size(),
        reinterpret_cast<uint8_t*>(const_cast<char*>(signature->data())),
        &length);
  }

  if (OEMCrypto_SUCCESS != sts) {
    LOGD("GenerateSignature: OEMCrypto_GenerateSignature err=%d", sts);
    return false;
  }

  // TODO(fredgc): b/8878371
  // remove in K, when L1 library reports correct length.
  signature->resize(length);

  return true;
}

CdmResponseType CryptoSession::Decrypt(const CdmDecryptionParameters& params) {
  if (!is_destination_buffer_type_valid_) {
    if (!SetDestinationBufferType()) return UNKNOWN_ERROR;
  }

  AutoLock auto_lock(crypto_lock_);
  // Check if key needs to be selected
  if (params.is_encrypted) {
    if (key_id_.compare(*params.key_id) != 0) {
      if (SelectKey(*params.key_id)) {
        key_id_ = *params.key_id;
      } else {
        return NEED_KEY;
      }
    }
  }

  OEMCrypto_DestBufferDesc buffer_descriptor;
  buffer_descriptor.type =
      params.is_secure ? destination_buffer_type_ : OEMCrypto_BufferType_Clear;

  switch (buffer_descriptor.type) {
    case OEMCrypto_BufferType_Clear:
      buffer_descriptor.buffer.clear.address =
          static_cast<uint8_t*>(params.decrypt_buffer) +
          params.decrypt_buffer_offset;
      buffer_descriptor.buffer.clear.max_length = params.decrypt_buffer_length;
      break;
    case OEMCrypto_BufferType_Secure:
      buffer_descriptor.buffer.secure.handle = params.decrypt_buffer;
      buffer_descriptor.buffer.secure.offset = params.decrypt_buffer_offset;
      buffer_descriptor.buffer.secure.max_length = params.decrypt_buffer_length;
      break;
    case OEMCrypto_BufferType_Direct:
      buffer_descriptor.type = OEMCrypto_BufferType_Direct;
      buffer_descriptor.buffer.direct.is_video = params.is_video;
      break;
  }

  OEMCryptoResult sts = OEMCrypto_DecryptCTR(
      oec_session_id_, params.encrypt_buffer, params.encrypt_length,
      params.is_encrypted, &(*params.iv).front(), params.block_offset,
      &buffer_descriptor, params.subsample_flags);

  switch (sts) {
    case OEMCrypto_SUCCESS:
      break;
    case OEMCrypto_ERROR_INSUFFICIENT_RESOURCES:
      return INSUFFICIENT_CRYPTO_RESOURCES;
    case OEMCrypto_ERROR_KEY_EXPIRED:
      return NEED_KEY;
    default:
      return UNKNOWN_ERROR;
  }
  return NO_ERROR;
}

bool CryptoSession::GenerateNonce(uint32_t* nonce) {
  if (!nonce) {
    LOGE("input parameter is null");
    return false;
  }

  LOGV("CryptoSession::GenerateNonce: Lock");
  AutoLock auto_lock(crypto_lock_);

  return (OEMCrypto_SUCCESS == OEMCrypto_GenerateNonce(oec_session_id_, nonce));
}

bool CryptoSession::SetDestinationBufferType() {
  if (Properties::oem_crypto_use_secure_buffers()) {
    if (GetSecurityLevel() == kSecurityLevelL1) {
      destination_buffer_type_ = OEMCrypto_BufferType_Secure;
    } else {
      destination_buffer_type_ = OEMCrypto_BufferType_Clear;
    }
  } else if (Properties::oem_crypto_use_fifo()) {
    destination_buffer_type_ = OEMCrypto_BufferType_Direct;
  } else if (Properties::oem_crypto_use_userspace_buffers()) {
    destination_buffer_type_ = OEMCrypto_BufferType_Clear;
  } else {
    return false;
  }

  is_destination_buffer_type_valid_ = true;
  return true;
}

bool CryptoSession::RewrapDeviceRSAKey(const std::string& message,
                                       const std::string& signature,
                                       const std::string& nonce,
                                       const std::string& enc_rsa_key,
                                       const std::string& rsa_key_iv,
                                       std::string* wrapped_rsa_key) {
  LOGD("CryptoSession::RewrapDeviceRSAKey, session id=%ld",
       static_cast<uint32_t>(oec_session_id_));

  const uint8_t* signed_msg = reinterpret_cast<const uint8_t*>(message.data());
  const uint8_t* msg_rsa_key = NULL;
  const uint8_t* msg_rsa_key_iv = NULL;
  const uint32_t* msg_nonce = NULL;
  if (enc_rsa_key.size() >= MAC_KEY_SIZE && rsa_key_iv.size() >= KEY_IV_SIZE) {
    msg_rsa_key = signed_msg + GetOffset(message, enc_rsa_key);
    msg_rsa_key_iv = signed_msg + GetOffset(message, rsa_key_iv);
    msg_nonce = reinterpret_cast<const uint32_t*>(signed_msg +
                                                  GetOffset(message, nonce));
  }

  // Gets wrapped_rsa_key_length by passing NULL as uint8_t* wrapped_rsa_key
  // and 0 as wrapped_rsa_key_length.
  size_t wrapped_rsa_key_length = 0;
  OEMCryptoResult status = OEMCrypto_RewrapDeviceRSAKey(
      oec_session_id_, signed_msg, message.size(),
      reinterpret_cast<const uint8_t*>(signature.data()), signature.size(),
      msg_nonce, msg_rsa_key, enc_rsa_key.size(), msg_rsa_key_iv, NULL,
      &wrapped_rsa_key_length);
  if (status != OEMCrypto_ERROR_SHORT_BUFFER) {
    LOGE("OEMCrypto_RewrapDeviceRSAKey fails to get wrapped_rsa_key_length");
    return false;
  }

  wrapped_rsa_key->resize(wrapped_rsa_key_length);
  status = OEMCrypto_RewrapDeviceRSAKey(
      oec_session_id_, signed_msg, message.size(),
      reinterpret_cast<const uint8_t*>(signature.data()), signature.size(),
      msg_nonce, msg_rsa_key, enc_rsa_key.size(), msg_rsa_key_iv,
      reinterpret_cast<uint8_t*>(&(*wrapped_rsa_key)[0]),
      &wrapped_rsa_key_length);

  // TODO(fredgc): b/8878371
  // remove in K, when L1 library reports correct length.
  wrapped_rsa_key->resize(wrapped_rsa_key_length);

  if (OEMCrypto_SUCCESS != status) {
    LOGE("OEMCrypto_RewrapDeviceRSAKey fails with %d", status);
    return false;
  }

  return true;
}

bool CryptoSession::GetRandom(size_t data_length, uint8_t* random_data) {
  if (random_data == NULL) {
    LOGE("CryptoSession::GetRandom: random data destination not provided");
    return false;
  }
  OEMCryptoResult sts = OEMCrypto_GetRandom(random_data, data_length);

  if (sts != OEMCrypto_SUCCESS) {
    LOGE("OEMCrypto_GetRandom fails with %d", sts);
    return false;
  }

  return true;
}

};  // namespace wvcdm
