/*********************************************************************
 * level3.h
 *
 * (c) Copyright 2013 Google, Inc.
 *
 * Reference APIs needed to support Widevine's crypto algorithms.
 *********************************************************************/

#ifndef LEVEL3_OEMCRYPTO_H_
#define LEVEL3_OEMCRYPTO_H_

#include<stddef.h>
#include<stdint.h>

#include "OEMCryptoCENC.h"

namespace wvoec3 {

#define Level3_Initialize               _lcc01
#define Level3_Terminate                _lcc02
#define Level3_InstallKeybox            _lcc03
#define Level3_GetKeyData               _lcc04
#define Level3_IsKeyboxValid            _lcc05
#define Level3_GetRandom                _lcc06
#define Level3_GetDeviceID              _lcc07
#define Level3_WrapKeybox               _lcc08
#define Level3_OpenSession              _lcc09
#define Level3_CloseSession             _lcc10
#define Level3_DecryptCTR               _lcc11
#define Level3_GenerateDerivedKeys      _lcc12
#define Level3_GenerateSignature        _lcc13
#define Level3_GenerateNonce            _lcc14
#define Level3_LoadKeys                 _lcc15
#define Level3_RefreshKeys              _lcc16
#define Level3_SelectKey                _lcc17
#define Level3_RewrapDeviceRSAKey       _lcc18
#define Level3_LoadDeviceRSAKey         _lcc19
#define Level3_GenerateRSASignature     _lcc20
#define Level3_DeriveKeysFromSessionKey _lcc21
#define Level3_APIVersion               _lcc22
#define Level3_SecurityLevel            _lcc23
#define Level3_Generic_Encrypt          _lcc24
#define Level3_Generic_Decrypt          _lcc25
#define Level3_Generic_Sign             _lcc26
#define Level3_Generic_Verify           _lcc27

extern "C" {

OEMCryptoResult Level3_Initialize(void);
OEMCryptoResult Level3_Terminate(void);
OEMCryptoResult Level3_OpenSession(OEMCrypto_SESSION *session);
OEMCryptoResult Level3_CloseSession(OEMCrypto_SESSION session);
OEMCryptoResult Level3_GenerateDerivedKeys(OEMCrypto_SESSION session,
                                           const uint8_t *mac_key_context,
                                           uint32_t mac_key_context_length,
                                           const uint8_t *enc_key_context,
                                           uint32_t enc_key_context_length);
OEMCryptoResult Level3_GenerateNonce(OEMCrypto_SESSION session,
                                     uint32_t* nonce);
OEMCryptoResult Level3_GenerateSignature(OEMCrypto_SESSION session,
                                         const uint8_t* message,
                                         size_t message_length,
                                         uint8_t* signature,
                                         size_t* signature_length);
OEMCryptoResult Level3_LoadKeys(OEMCrypto_SESSION session,
                                const uint8_t* message,
                                size_t message_length,
                                const uint8_t* signature,
                                size_t signature_length,
                                const uint8_t* enc_mac_key_iv,
                                const uint8_t* enc_mac_key,
                                size_t num_keys,
                                const OEMCrypto_KeyObject* key_array);
OEMCryptoResult Level3_RefreshKeys(OEMCrypto_SESSION session,
                                   const uint8_t* message,
                                   size_t message_length,
                                   const uint8_t* signature,
                                   size_t signature_length,
                                   size_t num_keys,
                                   const OEMCrypto_KeyRefreshObject* key_array);
OEMCryptoResult Level3_SelectKey(const OEMCrypto_SESSION session,
                                 const uint8_t* key_id,
                                 size_t key_id_length);
OEMCryptoResult Level3_DecryptCTR(OEMCrypto_SESSION session,
                                     const uint8_t *data_addr,
                                     size_t data_length,
                                     bool is_encrypted,
                                     const uint8_t *iv,
                                     size_t block_offset,
                                     const OEMCrypto_DestBufferDesc* out_buffer,
                                     uint8_t subsample_flags);
OEMCryptoResult Level3_InstallKeybox(const uint8_t *keybox,
                                     size_t keyBoxLength);
OEMCryptoResult Level3_IsKeyboxValid(void);
OEMCryptoResult Level3_GetDeviceID(uint8_t* deviceID,
                                   size_t *idLength);
OEMCryptoResult Level3_GetKeyData(uint8_t* keyData,
                                  size_t *keyDataLength);
OEMCryptoResult Level3_GetRandom(uint8_t* randomData,
                                 size_t dataLength);
OEMCryptoResult Level3_WrapKeybox(const uint8_t *keybox,
                                  size_t keyBoxLength,
                                  uint8_t *wrappedKeybox,
                                  size_t *wrappedKeyBoxLength,
                                  const uint8_t *transportKey,
                                  size_t transportKeyLength);
OEMCryptoResult Level3_RewrapDeviceRSAKey(OEMCrypto_SESSION session,
                                          const uint8_t* message,
                                          size_t message_length,
                                          const uint8_t* signature,
                                          size_t signature_length,
                                          const uint32_t *nonce,
                                          const uint8_t* enc_rsa_key,
                                          size_t enc_rsa_key_length,
                                          const uint8_t* enc_rsa_key_iv,
                                          uint8_t* wrapped_rsa_key,
                                          size_t *wrapped_rsa_key_length);
OEMCryptoResult Level3_LoadDeviceRSAKey(OEMCrypto_SESSION session,
                                        const uint8_t* wrapped_rsa_key,
                                        size_t wrapped_rsa_key_length);
OEMCryptoResult Level3_GenerateRSASignature(OEMCrypto_SESSION session,
                                            const uint8_t* message,
                                            size_t message_length,
                                            uint8_t* signature,
                                            size_t *signature_length);
OEMCryptoResult Level3_DeriveKeysFromSessionKey(OEMCrypto_SESSION session,
                                                const uint8_t* enc_session_key,
                                                size_t enc_session_key_length,
                                                const uint8_t *mac_key_context,
                                                size_t mac_key_context_length,
                                                const uint8_t *enc_key_context,
                                                size_t enc_key_context_length);
uint32_t Level3_APIVersion();
const char* Level3_SecurityLevel();
OEMCryptoResult Level3_Generic_Encrypt(OEMCrypto_SESSION session,
                                       const uint8_t* in_buffer,
                                       size_t buffer_length,
                                       const uint8_t* iv,
                                       OEMCrypto_Algorithm algorithm,
                                       uint8_t* out_buffer);
OEMCryptoResult Level3_Generic_Decrypt(OEMCrypto_SESSION session,
                                       const uint8_t* in_buffer,
                                       size_t buffer_length,
                                       const uint8_t* iv,
                                       OEMCrypto_Algorithm algorithm,
                                       uint8_t* out_buffer);
OEMCryptoResult Level3_Generic_Sign(OEMCrypto_SESSION session,
                                    const uint8_t* in_buffer,
                                    size_t buffer_length,
                                    OEMCrypto_Algorithm algorithm,
                                    uint8_t* signature,
                                    size_t* signature_length);
OEMCryptoResult Level3_Generic_Verify(OEMCrypto_SESSION session,
                                      const uint8_t* in_buffer,
                                      size_t buffer_length,
                                      OEMCrypto_Algorithm algorithm,
                                      const uint8_t* signature,
                                      size_t signature_length);
};

}
#endif  // LEVEL3_OEMCRYPTO_H_
