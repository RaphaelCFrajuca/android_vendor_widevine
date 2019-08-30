// Copyright 2012 Google Inc. All Rights Reserved.
//
// OEMCrypto Client - wrapper class for C-style OEMCrypto interface
//
#ifndef CDM_BASE_CRYPTO_SESSSION_H_
#define CDM_BASE_CRYPTO_SESSSION_H_

#include <string>
#include <map>

#include "lock.h"
#include "oemcrypto_adapter.h"
#include "OEMCryptoCENC.h"
#include "wv_cdm_types.h"

namespace wvcdm {

class CryptoKey;
typedef std::map<CryptoKeyId, CryptoKey*> CryptoKeyMap;

class CryptoSession {
 public:
  CryptoSession();
  ~CryptoSession();

  bool ValidateKeybox();
  bool GetToken(std::string* token);
  CdmSecurityLevel GetSecurityLevel();
  bool GetDeviceUniqueId(std::string* device_id);
  bool GetSystemId(uint32_t* system_id);
  bool GetProvisioningId(std::string* provisioning_id);

  CdmResponseType Open() { return Open(kLevelDefault); }
  CdmResponseType Open(SecurityLevel requested_security_level);
  void Close();

  bool IsOpen() { return open_; }
  CryptoSessionId oec_session_id() { return oec_session_id_; }

  // Key request/response
  void GenerateRequestId(std::string& req_id_str);
  bool PrepareRequest(const std::string& key_deriv_message,
                      bool is_provisioning, std::string* signature);
  bool PrepareRenewalRequest(const std::string& message,
                             std::string* signature);
  CdmResponseType LoadKeys(const std::string& message,
                           const std::string& signature,
                           const std::string& mac_key_iv,
                           const std::string& mac_key,
                           int num_keys, const CryptoKey* key_array);
  bool LoadCertificatePrivateKey(std::string& wrapped_key);
  bool RefreshKeys(const std::string& message, const std::string& signature,
                   int num_keys, const CryptoKey* key_array);
  bool GenerateNonce(uint32_t* nonce);
  bool GenerateDerivedKeys(const std::string& message);
  bool GenerateDerivedKeys(const std::string& message,
                           const std::string& session_key);
  bool RewrapDeviceRSAKey(const std::string& message,
                          const std::string& signature,
                          const std::string& nonce,
                          const std::string& enc_rsa_key,
                          const std::string& rsa_key_iv,
                          std::string* wrapped_rsa_key);

  // Media data path
  bool SelectKey(const std::string& key_id);
  CdmResponseType Decrypt(const CdmDecryptionParameters& parameters);

  bool GetRandom(size_t data_length, uint8_t* random_data);

 private:
  void Init();
  void Terminate();
  void GenerateMacContext(const std::string& input_context,
                          std::string* deriv_context);
  void GenerateEncryptContext(const std::string& input_context,
                              std::string* deriv_context);
  bool GenerateSignature(const std::string& message, bool use_rsa,
                         std::string* signature);
  size_t GetOffset(std::string message, std::string field);
  bool SetDestinationBufferType();

  static const size_t kSignatureSize = 32;  // size for HMAC-SHA256 signature
  static Lock crypto_lock_;
  static bool initialized_;
  static int session_count_;

  bool open_;
  CryptoSessionId oec_session_id_;

  OEMCryptoBufferType destination_buffer_type_;
  bool is_destination_buffer_type_valid_;
  SecurityLevel requested_security_level_;

  KeyId key_id_;

  CORE_DISALLOW_COPY_AND_ASSIGN(CryptoSession);
};

};  // namespace wvcdm

#endif  // CDM_BASE_CRYPTO_SESSSION_H_
