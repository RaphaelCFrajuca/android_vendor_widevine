/*******************************************************************************
 *
 * Copyright 2013 Google Inc. All Rights Reserved.
 *
 * mock implementation of OEMCrypto APIs
 *
 ******************************************************************************/

#include "oemcrypto_engine_mock.h"

#include <iostream>
#include <vector>
#include <string.h>

#include "log.h"
#include "oemcrypto_key_mock.h"
#include "openssl/aes.h"
#include "openssl/bio.h"
#include "openssl/cmac.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/hmac.h"
#include "openssl/rand.h"
#include <openssl/rsa.h>
#include "openssl/sha.h"
#include "openssl/x509.h"
#include "string_conversions.h"
#include "wv_cdm_constants.h"


static const int kPssSaltLength = 20;

namespace {
// Increment counter for AES-CTR
void ctr128_inc(uint8_t* counter) {
  uint32_t n = 16;
  do {
    if (++counter[--n] != 0) return;
  } while (n>8);
}
void dump_openssl_error() {
  while (unsigned long err = ERR_get_error()) {
    char buffer[120];
    LOGE("openssl error -- %lu -- %s",
         err, ERR_error_string(err, buffer));
  }
}
}

namespace wvoec_mock {

SessionKeyTable::~SessionKeyTable() {
  for (KeyMap::iterator i = keys_.begin(); i != keys_.end(); ++i) {
    if (NULL != i->second) {
      delete i->second;
    }
  }
}

bool SessionKeyTable::Insert(const KeyId key_id, const Key& key_data) {
  if (keys_.find(key_id) != keys_.end()) return false;
  keys_[key_id] = new Key(key_data);
  return true;
}

Key* SessionKeyTable::Find(const KeyId key_id) {
  if (keys_.find(key_id) == keys_.end()) {
    return NULL;
  }
  return keys_[key_id];
}

void SessionKeyTable::Remove(const KeyId key_id) {
  if (keys_.find(key_id) != keys_.end()) {
    delete keys_[key_id];
    keys_.erase(key_id);
  }
}

bool SessionKeyTable::UpdateDuration(const KeyControlBlock& control) {
  for(KeyMap::iterator it = keys_.begin(); it != keys_.end(); ++it) {
    if (!it->second->UpdateDuration(control)) {
      return false;
    }
  }
  return true;
}

void SessionContext::Open() {
}

void SessionContext::Close() {
}

// Internal utility function to derive key using CMAC-128
bool SessionContext::DeriveKey(const std::vector<uint8_t>& key,
                               const std::vector<uint8_t>& context,
                               int counter,
                               std::vector<uint8_t>* out) {
  if (key.empty() || counter > 4 || context.empty() || out == NULL) {
    LOGE("[DeriveKey(): OEMCrypto_ERROR_INVALID_CONTEXT]");
    return false;
  }

  const EVP_CIPHER* cipher = EVP_aes_128_cbc();
  CMAC_CTX* cmac_ctx = CMAC_CTX_new();

  if (!CMAC_Init(cmac_ctx, &key[0], key.size(), cipher, 0)) {
    LOGE("[DeriveKey(): OEMCrypto_ERROR_CMAC_FAILURE]");
    return false;
  }

  std::vector<uint8_t> message;
  message.push_back(counter);
  message.insert(message.end(), context.begin(), context.end());

  if (!CMAC_Update(cmac_ctx, &message[0], message.size())) {
    LOGE("[DeriveKey(): OEMCrypto_ERROR_CMAC_FAILURE]");
    return false;
  }

  size_t reslen;
  uint8_t res[128];
  if (!CMAC_Final(cmac_ctx, res, &reslen)) {
    LOGE("[DeriveKey(): OEMCrypto_ERROR_CMAC_FAILURE]");
    return false;
  }

  out->assign(res, res + reslen);

  CMAC_CTX_free(cmac_ctx);

  return true;
}

bool SessionContext::DeriveKeys(const std::vector<uint8_t>& master_key,
                                const std::vector<uint8_t>& mac_key_context,
                                const std::vector<uint8_t>& enc_key_context) {
  // Generate derived key for mac key
  std::vector<uint8_t> mac_key_server;
  std::vector<uint8_t> mac_key_client;
  std::vector<uint8_t> mac_key_part2;
  if (!DeriveKey(master_key, mac_key_context, 1, &mac_key_server)) {
    return false;
  }
  if (!DeriveKey(master_key, mac_key_context, 2, &mac_key_part2)) {
    return false;
  }
  mac_key_server.insert(mac_key_server.end(), mac_key_part2.begin(), mac_key_part2.end());

  if (!DeriveKey(master_key, mac_key_context, 3, &mac_key_client)) {
    return false;
  }
  if (!DeriveKey(master_key, mac_key_context, 4, &mac_key_part2)) {
    return false;
  }
  mac_key_client.insert(mac_key_client.end(), mac_key_part2.begin(), mac_key_part2.end());

  // Generate derived key for encryption key
  std::vector<uint8_t> enc_key;
  if (!DeriveKey(master_key, enc_key_context, 1, &enc_key)) {
    return false;
  }

#if 0  // Print Derived Keys to stdout.
  std::cout << "  mac_key_context = " << wvcdm::b2a_hex(mac_key_context) << std::endl;
  std::cout << "  enc_key_context = " << wvcdm::b2a_hex(enc_key_context) << std::endl;
  std::cout << "  mac_key_server = " << wvcdm::b2a_hex(mac_key_server) << std::endl;
  std::cout << "  mac_key_client = " << wvcdm::b2a_hex(mac_key_client) << std::endl;
  std::cout << "  enc_key = " << wvcdm::b2a_hex(enc_key) << std::endl;
#endif

  set_mac_key_server(mac_key_server);
  set_mac_key_client(mac_key_client);
  set_encryption_key(enc_key);
  return true;
}

bool SessionContext::RSADeriveKeys(const std::vector<uint8_t>& enc_session_key,
                                   const std::vector<uint8_t>& mac_key_context,
                                   const std::vector<uint8_t>& enc_key_context) {
  if (!rsa_key_) {
    LOGE("[RSADeriveKeys(): no RSA key set]");
    return false;
  }
  if (enc_session_key.size() != static_cast<size_t>(RSA_size(rsa_key_))) {
    LOGE("[RSADeriveKeys(): encrypted session key is wrong size:%zu, should be %d]",
         enc_session_key.size(), RSA_size(rsa_key_));
    dump_openssl_error();
    return false;
  }
  session_key_.resize(RSA_size(rsa_key_));
  int decrypted_size = RSA_private_decrypt(enc_session_key.size(),
                                           &enc_session_key[0],
                                           &session_key_[0], rsa_key_,
                                           RSA_PKCS1_OAEP_PADDING);
  if (-1 == decrypted_size) {
    LOGE("[RSADeriveKeys(): error decrypting session key.]");
    dump_openssl_error();
    return false;
  }
  session_key_.resize(decrypted_size);
  if (decrypted_size != static_cast<int>(wvcdm::KEY_SIZE)) {
    LOGE("[RSADeriveKeys(): error.  session key is wrong size: %d.]",
         decrypted_size);
    dump_openssl_error();
    session_key_.clear();
    return false;
  }
  return DeriveKeys(session_key_, mac_key_context, enc_key_context);
}

// Utility function to generate a message signature
bool SessionContext::GenerateSignature(const uint8_t* message,
                                       size_t message_length,
                                       uint8_t* signature,
                                       size_t* signature_length) {

  if (message == NULL || message_length == 0 ||
      signature == NULL || signature_length == 0) {
    LOGE("[OEMCrypto_GenerateSignature(): OEMCrypto_ERROR_INVALID_CONTEXT]");
    return false;
  }

  if (mac_key_client_.empty() || mac_key_client_.size() != wvcdm::MAC_KEY_SIZE) {
    LOGE("[GenerateSignature(): No MAC Key]");
    return false;
  }

  if (*signature_length < SHA256_DIGEST_LENGTH) {
    *signature_length = SHA256_DIGEST_LENGTH;
    return false;
  }

  unsigned int md_len = *signature_length;
  if (HMAC(EVP_sha256(), &mac_key_client_[0], SHA256_DIGEST_LENGTH,
           message, message_length, signature, &md_len)) {
    *signature_length = md_len;
    return true;
  }
  return false;
}

size_t SessionContext::RSASignatureSize() {
  if (!rsa_key_) {
    LOGE("[GenerateRSASignature(): no RSA key set]");
    return 0;
  }
  return static_cast<size_t>(RSA_size(rsa_key_));
}

bool SessionContext::GenerateRSASignature(const uint8_t* message,
                                          size_t message_length,
                                          uint8_t* signature,
                                          size_t* signature_length) {
  if (message == NULL || message_length == 0 ||
      signature == NULL || signature_length == 0) {
    LOGE("[GenerateRSASignature(): OEMCrypto_ERROR_INVALID_CONTEXT]");
    return false;
  }
  if (!rsa_key_) {
    LOGE("[GenerateRSASignature(): no RSA key set]");
    return false;
  }
  if (*signature_length < static_cast<size_t>(RSA_size(rsa_key_))) {
    *signature_length = RSA_size(rsa_key_);
    return false;
  }

  // Hash the message using SHA1.
  uint8_t hash[SHA_DIGEST_LENGTH];
  if (!SHA1(message, message_length, hash)) {
    LOGE("[GeneratRSASignature(): error creating signature hash.]");
    dump_openssl_error();
    return false;
  }

  // Add PSS padding.
  std::vector<uint8_t> padded_digest(*signature_length);
  int status = RSA_padding_add_PKCS1_PSS(rsa_key_, &padded_digest[0], hash,
                                         EVP_sha1(), kPssSaltLength);
  if (status == -1) {
    LOGE("[GeneratRSASignature(): error padding hash.]");
    dump_openssl_error();
    return false;
  }

  // Encrypt PSS padded digest.
  status = RSA_private_encrypt(*signature_length, &padded_digest[0], signature,
                               rsa_key_, RSA_NO_PADDING);
  if (status == -1) {
    LOGE("[GeneratRSASignature(): error in private encrypt.]");
    dump_openssl_error();
    return false;
  }
  return true;
}

// Validate message signature
bool SessionContext::ValidateMessage(const uint8_t* given_message,
                                     size_t message_length,
                                     const uint8_t* given_signature,
                                     size_t signature_length) {

  if (signature_length != SHA256_DIGEST_LENGTH) {
    return false;
  }
  uint8_t computed_signature[SHA256_DIGEST_LENGTH];
  unsigned int md_len = SHA256_DIGEST_LENGTH;
  if (!HMAC(EVP_sha256(), &mac_key_server_[0], SHA256_DIGEST_LENGTH,
            given_message, message_length, computed_signature, &md_len)) {
    LOGE("ValidateMessage: Could not compute signature.");
    return false;
  }
  if (memcmp(given_signature, computed_signature, signature_length)) {
    LOGE("Invalid signature    given: %s",
         wvcdm::HexEncode(given_signature, signature_length).c_str());
    LOGE("Invalid signature computed: %s",
         wvcdm::HexEncode(computed_signature, signature_length).c_str());
    return false;
  }
  return true;
}

bool SessionContext::ParseKeyControl(
    const std::vector<uint8_t>& key_control_string,
    KeyControlBlock& key_control_block) {

  key_control_block.Invalidate();

  if (key_control_string.size() < wvcdm::KEY_CONTROL_SIZE) {
    LOGD("ParseKeyControl: wrong size.");
    return false;
  }
  if (!key_control_block.SetFromString(key_control_string)) {
    LOGE("KCB: BAD Size or Structure");
    return false;
  }

  LOGD("KCB:");
  LOGD("  valid:    %d", key_control_block.valid());
  LOGD("  duration: %d", key_control_block.duration());
  LOGD("  nonce:    %08X", key_control_block.nonce());
  LOGD("  bits:     %08X", key_control_block.control_bits());
  LOGD("  bit kControlAllowEncrypt %s.",
       (key_control_block.control_bits() & kControlAllowEncrypt) ? "set" : "unset");
  LOGD("  bit kControlAllowDecrypt %s.",
       (key_control_block.control_bits() & kControlAllowDecrypt) ? "set" : "unset");
  LOGD("  bit kControlAllowSign %s.",
       (key_control_block.control_bits() & kControlAllowSign) ? "set" : "unset");
  LOGD("  bit kControlAllowVerify %s.",
       (key_control_block.control_bits() & kControlAllowVerify) ? "set" : "unset");
  LOGD("  bit kControlObserveDataPath %s.",
       (key_control_block.control_bits() & kControlObserveDataPath) ? "set" : "unset");
  LOGD("  bit kControlObserveHDCP %s.",
       (key_control_block.control_bits() & kControlObserveHDCP) ? "set" : "unset");
  LOGD("  bit kControlObserveCGMS %s.",
       (key_control_block.control_bits() & kControlObserveCGMS) ? "set" : "unset");
  LOGD("  bit kControlDataPathSecure %s.",
       (key_control_block.control_bits() & kControlDataPathSecure) ? "set" : "unset");
  LOGD("  bit kControlNonceEnabled %s.",
       (key_control_block.control_bits() & kControlNonceEnabled) ? "set" : "unset");
  LOGD("  bit kControlHDCPRequired %s.",
       (key_control_block.control_bits() & kControlHDCPRequired) ? "set" : "unset");
  uint32_t cgms_bits = key_control_block.control_bits() & 0x3;
  const char* cgms_values[4] = {"free", "BAD", "once", "never"};
  LOGD("    CGMS = %s", cgms_values[cgms_bits]);

  if (!key_control_block.Validate()) {
    LOGE("KCB: BAD Signature");
    return false;
  }
  if ((key_control_block.control_bits() & kControlNonceEnabled)
      && (!CheckNonce(key_control_block.nonce()))) {
    LOGE("KCB: BAD Nonce");
    return false;
  }

  return true;
}

void SessionContext::StartTimer() {
  timer_start_ = time(NULL);
}

uint32_t SessionContext::CurrentTimer() {
  time_t now = time(NULL);
  return now - timer_start_;
}

bool SessionContext::InstallKey(const KeyId& key_id,
                                const std::vector<uint8_t>& key_data,
                                const std::vector<uint8_t>& key_data_iv,
                                const std::vector<uint8_t>& key_control,
                                const std::vector<uint8_t>& key_control_iv) {

  // Decrypt encrypted key_data using derived encryption key and offered iv
  std::vector<uint8_t> content_key;
  std::vector<uint8_t> key_control_str;
  KeyControlBlock key_control_block;

  if (!ce_->DecryptMessage(this, encryption_key_, key_data_iv,
                           key_data, &content_key)) {
    LOGE("[Installkey(): Could not decrypt key data]");
    return false;
  }

#if 0  // Print content key to stdout.
  std::cout << "  InstallKey: key_id      = "
            << wvcdm::b2a_hex(key_id) << std::endl;
  std::cout << "  InstallKey: content_key = "
            << wvcdm::b2a_hex(content_key) << std::endl;
  std::cout << "  InstallKey: key_control = "
            << wvcdm::b2a_hex(key_control_str) << std::endl;
#endif

  // Key control must be supplied by license server
  if (key_control.empty()) {
    LOGE("[Installkey(): WARNING: No Key Control]");
    key_control_block.Invalidate();
    return false;
  } else {
    if (key_control_iv.empty()) {
      LOGE("[Installkey(): ERROR: No Key Control IV]");
      return false;
    }
    if (!ce_->DecryptMessage(this, content_key, key_control_iv,
                             key_control, &key_control_str)) {
      LOGE("[Installkey(): ERROR: Could not decrypt content key]");
      return false;
    }

    if (!ParseKeyControl(key_control_str, key_control_block)) {
      LOGE("Error parsing key control.");
      return false;
    }
  }

  Key key(KEYTYPE_CONTENT, content_key, key_control_block);
  session_keys_.Insert(key_id, key);
  return true;
}

bool  SessionContext::DecryptRSAKey(const uint8_t* enc_rsa_key,
                                    size_t enc_rsa_key_length,
                                    const uint8_t* enc_rsa_key_iv,
                                    uint8_t* pkcs8_rsa_key)  {
  // Decrypt rsa key with keybox.
  uint8_t iv_buffer[ wvcdm::KEY_IV_SIZE];
  memcpy(iv_buffer, enc_rsa_key_iv, wvcdm::KEY_IV_SIZE);
  AES_KEY aes_key;
  AES_set_decrypt_key(&encryption_key_[0], 128, &aes_key);
  AES_cbc_encrypt(enc_rsa_key, pkcs8_rsa_key, enc_rsa_key_length,
                  &aes_key, iv_buffer, AES_DECRYPT);
  return true;
}

bool SessionContext::EncryptRSAKey(const uint8_t* pkcs8_rsa_key,
                                   size_t enc_rsa_key_length,
                                   const uint8_t* enc_rsa_key_iv,
                                   uint8_t* enc_rsa_key) {
  // Encrypt rsa key with keybox.
  uint8_t iv_buffer[ wvcdm::KEY_IV_SIZE];
  memcpy(iv_buffer, enc_rsa_key_iv, wvcdm::KEY_IV_SIZE);
  AES_KEY aes_key;
  AES_set_encrypt_key(&encryption_key_[0], 128, &aes_key);
  AES_cbc_encrypt(pkcs8_rsa_key, enc_rsa_key, enc_rsa_key_length,
                  &aes_key, iv_buffer, AES_ENCRYPT);
  return true;
}

bool SessionContext::LoadRSAKey(uint8_t* pkcs8_rsa_key,
                                size_t rsa_key_length,
                                const uint8_t* message,
                                size_t message_length,
                                const uint8_t* signature,
                                size_t signature_length) {

  // Validate message signature
  if (!ValidateMessage(message, message_length, signature, signature_length)) {
    LOGE("[LoadRSAKey(): Could not verify signature]");
    return false;
  }
  if (rsa_key_) {
    RSA_free(rsa_key_);
    rsa_key_ = NULL;
  }
  BIO *bio = BIO_new_mem_buf(pkcs8_rsa_key, rsa_key_length);
  if( bio == NULL ) {
    LOGE("[LoadRSAKey(): Could not allocate bio buffer]");
    return false;
  }
  bool success = true;
  PKCS8_PRIV_KEY_INFO *pkcs8_pki = d2i_PKCS8_PRIV_KEY_INFO_bio(bio, NULL);
  if (pkcs8_pki == NULL) {
    LOGE("d2i_PKCS8_PRIV_KEY_INFO_bio returned NULL.");
    success = false;
  }
  EVP_PKEY *evp = NULL;
  if (success) {
    evp = EVP_PKCS82PKEY(pkcs8_pki);
    if (evp == NULL) {
      LOGE("EVP_PKCS82PKEY returned NULL.");
      success = false;
    }
  }
  if (success) {
    rsa_key_ = EVP_PKEY_get1_RSA(evp);
    if (rsa_key_ == NULL) {
      LOGE("PrivateKeyInfo did not contain an RSA key.");
      success = false;
    }
  }
  if (evp != NULL) {
    EVP_PKEY_free(evp);
  }
  if (pkcs8_pki != NULL) {
    PKCS8_PRIV_KEY_INFO_free(pkcs8_pki);
  }
  BIO_free(bio);
  if (!success) {
    return false;
  }
  switch (RSA_check_key(rsa_key_)) {
  case 1: // valid.
    return true;
  case 0:  // not valid.
    LOGE("[LoadRSAKey(): rsa key not valid]");
    dump_openssl_error();
    return false;
  default:  // -1 == check failed.
    LOGE("[LoadRSAKey(): error checking rsa key]");
    dump_openssl_error();
    return false;
  }
}

bool SessionContext::Generic_Encrypt(const uint8_t* in_buffer,
                                     size_t buffer_length,
                                     const uint8_t* iv,
                                     OEMCrypto_Algorithm algorithm,
                                     uint8_t* out_buffer) {
  // Check there is a content key
  if (current_content_key() == NULL) {
    LOGE("[Generic_Encrypt(): OEMCrypto_ERROR_NO_CONTENT_KEY]");
    return false;
  }
  const std::vector<uint8_t>& key = current_content_key()->value();
  const KeyControlBlock& control = current_content_key()->control();
  // Set the AES key.
  if (static_cast<int>(key.size()) != AES_BLOCK_SIZE) {
    LOGE("[Generic_Encrypt(): CONTENT_KEY has wrong size: %d",key.size());
    return false;
  }
  if (!(control.control_bits() & kControlAllowEncrypt)) {
    LOGE("[Generic_Encrypt(): control bit says not allowed.");
    return false;
  }
  if (control.duration() > 0) {
    if (control.duration() < CurrentTimer()) {
      LOGE("[Generic_Encrypt(): key expired.");
      return false;
    }
  }
  if( algorithm != OEMCrypto_AES_CBC_128_NO_PADDING ) {
    LOGE("[Generic_Encrypt(): algorithm bad.");
    return false;
  }
  if( buffer_length % AES_BLOCK_SIZE != 0 ) {
    LOGE("[Generic_Encrypt(): buffers size bad.");
    return false;
  }
  const uint8_t* key_u8 = &key[0];
  AES_KEY aes_key;
  if (AES_set_encrypt_key(key_u8, AES_BLOCK_SIZE * 8, &aes_key) != 0) {
    LOGE("[Generic_Encrypt(): FAILURE]");
    return false;
  }
  uint8_t iv_buffer[ wvcdm::KEY_IV_SIZE];
  memcpy(iv_buffer, iv, wvcdm::KEY_IV_SIZE);
  AES_cbc_encrypt(in_buffer, out_buffer, buffer_length,
                  &aes_key, iv_buffer, AES_ENCRYPT);
  return true;
}

bool SessionContext::Generic_Decrypt(const uint8_t* in_buffer,
                                               size_t buffer_length,
                                               const uint8_t* iv,
                                               OEMCrypto_Algorithm algorithm,
                                               uint8_t* out_buffer) {
  // Check there is a content key
  if (current_content_key() == NULL) {
    LOGE("[Generic_Decrypt(): OEMCrypto_ERROR_NO_CONTENT_KEY]");
    return false;
  }
  const std::vector<uint8_t>& key = current_content_key()->value();
  const KeyControlBlock& control = current_content_key()->control();
  // Set the AES key.
  if (static_cast<int>(key.size()) != AES_BLOCK_SIZE) {
    LOGE("[Generic_Decrypt(): CONTENT_KEY has wrong size.");
    return false;
  }
  if (!(control.control_bits() & kControlAllowDecrypt)) {
    LOGE("[Generic_Decrypt(): control bit says not allowed.");
    return false;
  }
  if (control.control_bits() & kControlDataPathSecure) {
    LOGE("[Generic_Decrypt(): control bit says secure path only.");
    return false;
  }
  if (control.duration() > 0) {
    if (control.duration() < CurrentTimer()) {
      LOGE("[Generic_Decrypt(): key expired.");
      return false;
    }
  }
  if( algorithm != OEMCrypto_AES_CBC_128_NO_PADDING ) {
    LOGE("[Generic_Decrypt(): bad algorithm.");
    return false;
  }
  if( buffer_length % AES_BLOCK_SIZE != 0 ) {
    LOGE("[Generic_Decrypt(): bad buffer size.");
    return false;
  }
  const uint8_t* key_u8 = &key[0];
  AES_KEY aes_key;
  if (AES_set_decrypt_key(key_u8, AES_BLOCK_SIZE * 8, &aes_key) != 0) {
    LOGE("[Generic_Decrypt(): FAILURE]");
    return false;
  }
  uint8_t iv_buffer[ wvcdm::KEY_IV_SIZE];
  memcpy(iv_buffer, iv, wvcdm::KEY_IV_SIZE);
  AES_cbc_encrypt(in_buffer, out_buffer, buffer_length,
                  &aes_key, iv_buffer, AES_DECRYPT);
  return true;
}

bool SessionContext::Generic_Sign(const uint8_t* in_buffer,
                                            size_t buffer_length,
                                            OEMCrypto_Algorithm algorithm,
                                            uint8_t* signature,
                                            size_t* signature_length) {
  // Check there is a content key
  if (current_content_key() == NULL) {
    LOGE("[Generic_Sign(): OEMCrypto_ERROR_NO_CONTENT_KEY]");
    return false;
  }
  if (*signature_length < SHA256_DIGEST_LENGTH) {
    *signature_length = SHA256_DIGEST_LENGTH;
    LOGE("[Generic_Sign(): bad signature length.");
    return false;
  }
  const std::vector<uint8_t>& key = current_content_key()->value();
  const KeyControlBlock& control = current_content_key()->control();
  if (static_cast<int>(key.size()) != SHA256_DIGEST_LENGTH) {
    LOGE("[Generic_Sign(): CONTENT_KEY has wrong size; %d", key.size());
    return false;
  }
  if (!(control.control_bits() & kControlAllowSign)) {
    LOGE("[Generic_Sign(): control bit says not allowed.");
    return false;
  }
  if (control.duration() > 0) {
    if (control.duration() < CurrentTimer()) {
      LOGE("[Generic_Sign(): key expired.");
      return false;
    }
  }
  if( algorithm != OEMCrypto_HMAC_SHA256 ) {
    LOGE("[Generic_Sign(): bad algorithm.");
    return false;
  }
  unsigned int md_len = *signature_length;
  if (HMAC(EVP_sha256(), &key[0], SHA256_DIGEST_LENGTH,
           in_buffer, buffer_length, signature, &md_len)) {
    *signature_length = md_len;
    return true;
  }
  LOGE("[Generic_Sign(): hmac failed.");
  dump_openssl_error();
  return false;
}

bool SessionContext::Generic_Verify(const uint8_t* in_buffer,
                                    size_t buffer_length,
                                    OEMCrypto_Algorithm algorithm,
                                    const uint8_t* signature,
                                    size_t signature_length) {
  // Check there is a content key
  if (current_content_key() == NULL) {
    LOGE("[Decrypt_Verify(): OEMCrypto_ERROR_NO_CONTENT_KEY]");
    return false;
  }
  if (signature_length < SHA256_DIGEST_LENGTH) {
    return false;
  }
  const std::vector<uint8_t>& key = current_content_key()->value();
  const KeyControlBlock& control = current_content_key()->control();
  if (static_cast<int>(key.size()) != SHA256_DIGEST_LENGTH) {
    LOGE("[Generic_Verify(): CONTENT_KEY has wrong size: %d", key.size());
    return false;
  }
  if (!(control.control_bits() & kControlAllowVerify)) {
    LOGE("[Generic_Verify(): control bit says not allowed.");
    return false;
  }
  if (control.duration() > 0) {
    if (control.duration() < CurrentTimer()) {
      LOGE("[Generic_Verify(): key expired.");
      return false;
    }
  }
  if( algorithm != OEMCrypto_HMAC_SHA256 ) {
    LOGE("[Generic_Verify(): bad algorithm.");
    return false;
  }
  unsigned int md_len = signature_length;
  uint8_t computed_signature[SHA256_DIGEST_LENGTH];
  if (HMAC(EVP_sha256(), &key[0], SHA256_DIGEST_LENGTH,
           in_buffer, buffer_length, computed_signature, &md_len)) {
    return (0 == memcmp( signature, computed_signature, SHA256_DIGEST_LENGTH));
  }
  LOGE("[Generic_Verify(): HMAC failed.");
  dump_openssl_error();
  return false;
}

bool SessionContext::RefreshKey(const KeyId& key_id,
                                const std::vector<uint8_t>& key_control,
                                const std::vector<uint8_t>& key_control_iv) {
  if (key_id.empty()) {
    // Key control is not encrypted if key id is NULL
    KeyControlBlock key_control_block(true);
    if (!ParseKeyControl(key_control, key_control_block)) {
      LOGD("Parse key control error.");
      return false;
    }
    // Apply duration to all keys in this session
    return session_keys_.UpdateDuration(key_control_block);
  }

  Key* content_key = session_keys_.Find(key_id);

  if (NULL == content_key) {
    LOGD("Error: no matching content key.");
    return false;
  }

  if (key_control.empty()) {
    LOGD("Error: no key_control.");
    return false;
  }

  const std::vector<uint8_t> content_key_value = content_key->value();

  // Decrypt encrypted key control block
  std::vector<uint8_t> control;
  if (key_control_iv.empty()) {
    // TODO(fredg): get confirmation from server team this is valid.
    LOGD("Key control block is NOT encrypted.");
    control = key_control;
  } else {
    // TODO(fredg): get confirmation from server team this is valid, too.
    LOGD("Key control block is encrypted.");
    if (!ce_->DecryptMessage(this, content_key_value, key_control_iv,
                             key_control, &control)) {
      LOGD("Error decrypting key control block.");
      return false;
    }
  }

  KeyControlBlock key_control_block(true);
  if (!ParseKeyControl(control, key_control_block)) {
    LOGD("Error parsing key control.");
    return false;
  }

  if (!content_key->UpdateDuration(key_control_block)) {
    LOGD("Error updating duration.");
    return false;
  }

  return true;
}

bool SessionContext::UpdateMacKeys(const std::vector<uint8_t>& enc_mac_keys,
                                   const std::vector<uint8_t>& iv) {

  // Decrypt mac key from enc_mac_key using device_keya
  std::vector<uint8_t> mac_keys;
  if (!ce_->DecryptMessage(this, encryption_key_, iv,
                           enc_mac_keys, &mac_keys)) {
    return false;
  }
  mac_key_server_ = std::vector<uint8_t>(mac_keys.begin(),
                                         mac_keys.begin()+wvcdm::MAC_KEY_SIZE);
  mac_key_client_ = std::vector<uint8_t>(mac_keys.begin()+wvcdm::MAC_KEY_SIZE,
                                         mac_keys.end());
  return true;
}

bool SessionContext::SelectContentKey(const KeyId& key_id) {
  const Key* content_key = session_keys_.Find(key_id);
#if 0
  std::cout << "  Select Key: key_id      = "
            << wvcdm::b2a_hex(key_id) << std::endl;
  std::cout << "  Select Key: key = "
            << wvcdm::b2a_hex(content_key->value()) << std::endl;
#endif
  if (NULL == content_key) {
    LOGE("[SelectContentKey(): No key matches key id]");
    return false;
  }
  current_content_key_ = content_key;
  return true;
}

void SessionContext::AddNonce(uint32_t nonce) {
  nonce_table_.AddNonce(nonce);
}

bool SessionContext::CheckNonce(uint32_t nonce) {
  return nonce_table_.CheckNonce(nonce);
}

void SessionContext::FlushNonces() {
  nonce_table_.Flush();
}

CryptoEngine::CryptoEngine() :
    ce_state_(CE_INITIALIZED), current_session_(NULL) {
  valid_ = true;
  ERR_load_crypto_strings();
}

CryptoEngine::~CryptoEngine() {
  current_session_ = NULL;
  sessions_.clear();
}

void CryptoEngine::Terminate() {
}

KeyboxError CryptoEngine::ValidateKeybox() { return keybox_.Validate(); }

SessionId CryptoEngine::CreateSession() {
  wvcdm::AutoLock lock(session_table_lock_);
  static int unique_id = 1;
  SessionId sid = (SessionId)++unique_id;
  SessionContext* sctx = new SessionContext(this, sid);
  sessions_[sid] = sctx;
  return sid;
}

bool CryptoEngine::DestroySession(SessionId sid) {
  SessionContext* sctx = FindSession(sid);
  wvcdm::AutoLock lock(session_table_lock_);
  if (sctx) {
    sessions_.erase(sid);
    delete sctx;
    return true;
  } else {
    return false;
  }
}

SessionContext* CryptoEngine::FindSession(SessionId sid) {
  wvcdm::AutoLock lock(session_table_lock_);
  ActiveSessions::iterator it = sessions_.find(sid);
  if (it != sessions_.end()) {
    return it->second;
  }
  return NULL;
}

// Internal utility function to decrypt the message
bool CryptoEngine::DecryptMessage(SessionContext* session,
                                  const std::vector<uint8_t>& key,
                                  const std::vector<uint8_t>& iv,
                                  const std::vector<uint8_t>& message,
                                  std::vector<uint8_t>* decrypted) {
  if (key.empty() || iv.empty() || message.empty() || !decrypted) {
    LOGE("[DecryptMessage(): OEMCrypto_ERROR_INVALID_CONTEXT]");
    return false;
  }
  decrypted->resize(message.size());
  uint8_t iv_buffer[16];
  memcpy(iv_buffer, &iv[0], 16);
  AES_KEY aes_key;
  AES_set_decrypt_key(&key[0], 128, &aes_key);
  AES_cbc_encrypt(&message[0], &(decrypted->front()), message.size(),
                  &aes_key, iv_buffer, AES_DECRYPT);
  return true;
}

bool CryptoEngine::DecryptCTR(SessionContext* session,
                              const uint8_t* iv,
                              size_t block_offset,
                              const uint8_t* cipher_data,
                              size_t cipher_data_length,
                              bool is_encrypted,
                              void* clear_data,
                              BufferType buffer_type) {

  // If the data is clear, we do not need a current key selected.
  if (!is_encrypted) {
    memcpy(reinterpret_cast<uint8_t*>(clear_data),
           cipher_data, cipher_data_length);
    return true;
  }

  // Check there is a content key
  if (session->current_content_key() == NULL) {
    LOGE("[DecryptCTR(): OEMCrypto_ERROR_NO_CONTENT_KEY]");
    return false;
  }
  const KeyControlBlock& control = session->current_content_key()->control();
  if (control.control_bits() & kControlDataPathSecure) {
    if (buffer_type == kBufferTypeClear) {
      LOGE("[DecryptCTR(): Secure key with insecure buffer]");
      return false;
    }
  }
  if (control.control_bits() & kControlHDCPRequired) {
    // For reference implementation, we do not implement any HDCP.
    return false;
  }
  if (control.duration() > 0) {
    if (control.duration() < session->CurrentTimer()) {
      return false;
    }
  }

  const std::vector<uint8_t>& content_key = session->current_content_key()->value();

  // Set the AES key.
  if (static_cast<int>(content_key.size()) != AES_BLOCK_SIZE) {
    LOGE("[DecryptCTR(): CONTENT_KEY has wrong size: %d", content_key.size());
    return false;
  }
  const uint8_t* key_u8 = &content_key[0];
  AES_KEY aes_key;
  if (AES_set_encrypt_key(key_u8, AES_BLOCK_SIZE * 8, &aes_key) != 0) {
    LOGE("[DecryptCTR(): FAILURE]");
    return false;
  }

  if (buffer_type == kBufferTypeDirect) {
    // For reference implementation, we quietly drop direct video.
    return true;
  }

  if (buffer_type == kBufferTypeSecure) {
    // For reference implementation, we also quietly drop secure data.
    return true;
  }

  // Local copy (will be modified).
  uint8_t aes_iv[AES_BLOCK_SIZE];
  memcpy(aes_iv, &iv[0], AES_BLOCK_SIZE);

  // Encrypt the IV.
  uint8_t ecount_buf[AES_BLOCK_SIZE];
  if (block_offset != 0) {
    // The context is needed only when not starting a new block.
    AES_encrypt(aes_iv, ecount_buf, &aes_key);
    ctr128_inc(aes_iv);
  }

  // Decryption.
  unsigned int block_offset_cur = block_offset;
  AES_ctr128_encrypt(
      cipher_data, reinterpret_cast<uint8_t*>(clear_data), cipher_data_length,
      &aes_key, aes_iv, ecount_buf, &block_offset_cur);
  if (block_offset_cur != ((block_offset + cipher_data_length) % AES_BLOCK_SIZE)) {
    LOGE("[DecryptCTR(): FAILURE: byte offset wrong.]");
    return false;
  }
  return true;
}

void NonceTable::AddNonce(uint32_t nonce) {
  int new_slot = -1;
  int oldest_slot = -1;

  // Flush any nonces that have been checked but not flushed.
  // After flush, nonces will be either valid or invalid.
  Flush();

  for (int i = 0; i < kTableSize; ++i) {
    // Increase age of all valid nonces.
    if (kNTStateValid == state_[i]) {
      ++age_[i];
      if (-1 == oldest_slot) {
        oldest_slot = i;
      } else {
        if (age_[i] > age_[oldest_slot]) {
          oldest_slot = i;
        }
      }
    } else {
      if (-1 == new_slot) {
        age_[i] = 0;
        nonces_[i] = nonce;
        state_[i] = kNTStateValid;
        new_slot = i;
      }
    }
  }
  if (-1 == new_slot) {
    // reuse oldest
    // assert (oldest_slot != -1)
    int i = oldest_slot;
    age_[i] = 0;
    nonces_[i] = nonce;
    state_[i] = kNTStateValid;
  }
}

bool NonceTable::CheckNonce(uint32_t nonce) {
  for (int i = 0; i < kTableSize; ++i) {
    if (kNTStateInvalid != state_[i]) {
      if (nonce == nonces_[i]) {
        state_[i] = kNTStateFlushPending;
        return true;
      }
    }
  }
  return false;
}

void NonceTable::Flush() {
  for (int i = 0; i < kTableSize; ++i) {
    if (kNTStateFlushPending == state_[i]) {
      state_[i] = kNTStateInvalid;
    }
  }
}

}; // namespace wvoec_mock
