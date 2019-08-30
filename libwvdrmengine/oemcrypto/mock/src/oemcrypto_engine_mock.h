/*******************************************************************************
 *
 * Copyright 2013 Google Inc. All Rights Reserved.
 *
 * mock implementation of OEMCrypto APIs
 *
 ******************************************************************************/

#ifndef OEMCRYPTO_ENGINE_MOCK_H_
#define OEMCRYPTO_ENGINE_MOCK_H_

#include <openssl/rsa.h>
#include <stdint.h>
#include <time.h>
#include <map>
#include <vector>

#include "lock.h"
#include "oemcrypto_key_mock.h"
#include "oemcrypto_keybox_mock.h"
#include "wv_cdm_types.h"

// TODO(fredgc,gmorgan): Revisit the need to keep interface separate.
// For now, we need to include the enum OEMCrypto_Algorithm.
#include "OEMCryptoCENC.h"

namespace wvoec_mock {

enum BufferType {
  kBufferTypeClear,
  kBufferTypeSecure,
  kBufferTypeDirect
};

class SessionContext;
class CryptoEngine;

typedef uint32_t SessionId;
typedef std::map<SessionId, SessionContext*> ActiveSessions;

typedef std::vector<uint8_t>  KeyId;
typedef std::map<KeyId, Key*> KeyMap;

// SessionKeyTable holds the keys for the current session
class SessionKeyTable {
 public:
  SessionKeyTable() {}
  ~SessionKeyTable();

  bool Insert(const KeyId key_id, const Key& key_data);
  Key* Find(const KeyId key_id);
  void Remove(const KeyId key_id);
  bool UpdateDuration(const KeyControlBlock& control);

 private:
  KeyMap keys_;

  CORE_DISALLOW_COPY_AND_ASSIGN(SessionKeyTable);
};

class NonceTable {
 public:
  static const int kTableSize = 16;
  NonceTable() {
    for (int i = 0; i < kTableSize; ++i) {
      state_[i] = kNTStateInvalid;
    }
  }
  ~NonceTable() {};
  void AddNonce(uint32_t nonce);
  bool CheckNonce(uint32_t nonce);
  void Flush();
 private:
  enum NonceTableState {
    kNTStateInvalid,
    kNTStateValid,
    kNTStateFlushPending
  };
  NonceTableState state_[kTableSize];
  uint32_t age_[kTableSize];
  uint32_t nonces_[kTableSize];
};

class SessionContext {
 private:
  SessionContext() {}

 public:
  explicit SessionContext(CryptoEngine* ce, SessionId sid)
      : valid_(true), ce_(ce), id_(sid), current_content_key_(NULL),
        rsa_key_(NULL) {}
  ~SessionContext() {}

  void Open();
  void Close();

  bool isValid() { return valid_; }

  bool DeriveKeys(const std::vector<uint8_t>& master_key,
                  const std::vector<uint8_t>& mac_context,
                  const std::vector<uint8_t>& enc_context);
  bool RSADeriveKeys(const std::vector<uint8_t>& enc_session_key,
                     const std::vector<uint8_t>& mac_context,
                     const std::vector<uint8_t>& enc_context);
  bool GenerateSignature(const uint8_t* message,
                         size_t message_length,
                         uint8_t* signature,
                         size_t* signature_length);
  size_t RSASignatureSize();
  bool GenerateRSASignature(const uint8_t* message,
                            size_t message_length,
                            uint8_t* signature,
                            size_t* signature_length);
  bool ValidateMessage(const uint8_t* message,
                       size_t message_length,
                       const uint8_t* signature,
                       size_t signature_length);
  bool Generic_Encrypt(const uint8_t* in_buffer,
                       size_t buffer_length,
                       const uint8_t* iv,
                       OEMCrypto_Algorithm algorithm,
                       uint8_t* out_buffer);
  bool Generic_Decrypt(const uint8_t* in_buffer,
                       size_t buffer_length,
                       const uint8_t* iv,
                       OEMCrypto_Algorithm algorithm,
                       uint8_t* out_buffer);
  bool Generic_Sign(const uint8_t* in_buffer,
                    size_t buffer_length,
                    OEMCrypto_Algorithm algorithm,
                    uint8_t* signature,
                    size_t* signature_length);
  bool Generic_Verify(const uint8_t* in_buffer,
                      size_t buffer_length,
                      OEMCrypto_Algorithm algorithm,
                      const uint8_t* signature,
                      size_t signature_length);
  void StartTimer();
  uint32_t CurrentTimer(); // (seconds).
  bool InstallKey(const KeyId& key_id,
                  const std::vector<uint8_t>& key_data,
                  const std::vector<uint8_t>& key_data_iv,
                  const std::vector<uint8_t>& key_control,
                  const std::vector<uint8_t>& key_control_iv);
  bool DecryptRSAKey(const uint8_t* enc_rsa_key,
                     size_t enc_rsa_key_length,
                     const uint8_t* wrapped_rsa_key_iv,
                     uint8_t* pkcs8_rsa_key);
  bool EncryptRSAKey(const uint8_t* pkcs8_rsa_key,
                     size_t enc_rsa_key_length,
                     const uint8_t* enc_rsa_key_iv,
                     uint8_t* enc_rsa_key);
  bool LoadRSAKey(uint8_t* pkcs8_rsa_key,
                  size_t rsa_key_length,
                  const uint8_t* message,
                  size_t message_length,
                  const uint8_t* signature,
                  size_t signature_length);
  bool ParseKeyControl(const std::vector<uint8_t>& key_control_string,
                       KeyControlBlock& key_control_block);
  bool RefreshKey(const KeyId& key_id,
                  const std::vector<uint8_t>& key_control,
                  const std::vector<uint8_t>& key_control_iv);
  bool UpdateMacKeys(const std::vector<uint8_t>& mac_keys,
                     const std::vector<uint8_t>& iv);
  bool SelectContentKey(const KeyId& key_id);
  const Key* current_content_key(void) {return current_content_key_;}
  void set_mac_key_server(const std::vector<uint8_t>& mac_key_server) {
    mac_key_server_ = mac_key_server;
  }
  const std::vector<uint8_t>& mac_key_server() { return mac_key_server_; }
  void set_mac_key_client(const std::vector<uint8_t>& mac_key_client) {
    mac_key_client_ = mac_key_client; }
  const std::vector<uint8_t>& mac_key_client() { return mac_key_client_; }

  void set_encryption_key(const std::vector<uint8_t>& enc_key) {
    encryption_key_ = enc_key;
  }
  const std::vector<uint8_t>& encryption_key() { return encryption_key_; }

  void AddNonce(uint32_t nonce);
  bool CheckNonce(uint32_t nonce);
  void FlushNonces();

 private:

  bool DeriveKey(const std::vector<uint8_t>& key, const std::vector<uint8_t>& context,
                 int counter, std::vector<uint8_t>* out);

  bool valid_;
  CryptoEngine* ce_;
  SessionId id_;
  std::vector<uint8_t> mac_key_server_;
  std::vector<uint8_t> mac_key_client_;
  std::vector<uint8_t> encryption_key_;
  std::vector<uint8_t> session_key_;
  const Key* current_content_key_;
  SessionKeyTable session_keys_;
  NonceTable nonce_table_;
  RSA* rsa_key_;
  time_t timer_start_;

  CORE_DISALLOW_COPY_AND_ASSIGN(SessionContext);
};

class CryptoEngine {

 private:

  enum CryptoEngineState {
    CE_ILLEGAL,
    CE_INITIALIZED,
    CE_HAS_KEYBOX,
    CE_HAS_SESSIONS,
    CE_ERROR
  };

 public:

  CryptoEngine();
  ~CryptoEngine();

  bool Initialized() { return (ce_state_ != CE_ILLEGAL); }

  void Terminate();

  bool isValid() { return valid_; }

  KeyboxError ValidateKeybox();
  WvKeybox& keybox() { return keybox_; }

  SessionId CreateSession();

  bool DestroySession(SessionId sid);

  SessionContext* FindSession(SessionId sid);

  void set_current_session_(SessionContext* current) {
    current_session_ = current;
  }

  bool DecryptMessage(SessionContext* session,
                      const std::vector<uint8_t>& key,
                      const std::vector<uint8_t>& iv,
                      const std::vector<uint8_t>& message,
                      std::vector<uint8_t>* decrypted);

  bool DecryptCTR(SessionContext* session,
                  const uint8_t* iv,
                  size_t block_offset,
                  const uint8_t* cipher_data,
                  size_t cipher_data_length,
                  bool is_encrypted,
                  void* clear_data,
                  BufferType buffer_type);

 private:

  bool valid_;
  CryptoEngineState ce_state_;
  SessionContext* current_session_;
  ActiveSessions sessions_;
  WvKeybox keybox_;
  wvcdm::Lock session_table_lock_;

  CORE_DISALLOW_COPY_AND_ASSIGN(CryptoEngine);
};

};   // namespace wvoec_eng
#endif
