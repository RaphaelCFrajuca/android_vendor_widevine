// Copyright 2013 Google Inc. All Rights Reserved.
//
// Original code at //depot/google3/video/widevine/common/rsa_key.cc by
// tinskip@google.com. Modified for core CDM usage.
//
// Description:
//   Definition of classes representing RSA public keys used
//   for signature verification and encryption and decryption.
//

#include "privacy_crypto.h"

#include "log.h"
#include "openssl/aes.h"
#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/pem.h"
#include "openssl/sha.h"

namespace {
const int kPssSaltLength = 20;
const int kRsaPkcs1OaepPaddingLength = 41;
}  // namespace

namespace wvcdm {

bool AesCbcKey::Init(const std::string& key) {
  if (key.empty()) {
    LOGE("AesCbcKey::Init: no key provided");
    return false;
  }
  if (key.size() != AES_BLOCK_SIZE) {
    LOGE("AesCbcKey::Init: unexpected key size: %d", key.size());
    return false;
  }

  EVP_CIPHER_CTX_init(&ctx_);
  if (EVP_EncryptInit(&ctx_, EVP_aes_128_cbc(),
                      reinterpret_cast<const uint8_t*>(&key[0]), NULL) == 0) {
    LOGE("AesCbcKey::Init: AES CBC key setup failure: %s",
         ERR_error_string(ERR_get_error(), NULL));
    return false;
  }
  initialized_ = true;
  return true;
}

bool AesCbcKey::Encrypt(const std::string& in, std::string* out,
                        std::string* iv) {
  if (in.empty()) {
    LOGE("AesCbcKey::Encrypt: no cleartext provided");
    return false;
  }
  if (iv == NULL) {
    LOGE("AesCbcKey::Encrypt: initialization vector destination not provided");
    return false;
  }
  if (iv->size() != AES_BLOCK_SIZE) {
    LOGE("AesCbcKey::Encrypt: invalid iv size: %d", iv->size());
    return false;
  }
  if (out == NULL) {
    LOGE("AesCbcKey::Encrypt: crypttext destination not provided");
    return false;
  }
  if (!initialized_) {
    LOGE("AesCbcKey::Encrypt: AES key not initialized");
    return false;
  }

  if (EVP_EncryptInit(&ctx_, NULL, NULL,
                      reinterpret_cast<const uint8_t*>(iv->data())) == 0) {
    LOGE("AesCbcKey::Encrypt: AES CBC iv setup failure: %s",
         ERR_error_string(ERR_get_error(), NULL));
    return false;
  }

  out->resize(in.size() + AES_BLOCK_SIZE);
  int out_length = out->size();
  if (EVP_EncryptUpdate(
          &ctx_, reinterpret_cast<uint8_t*>(&(*out)[0]), &out_length,
          reinterpret_cast<uint8_t*>(const_cast<char*>(in.data())),
          in.size()) == 0) {
    LOGE("AesCbcKey::Encrypt: encryption failure: %s",
         ERR_error_string(ERR_get_error(), NULL));
    return false;
  }

  int padding = 0;
  if (EVP_EncryptFinal(&ctx_, reinterpret_cast<uint8_t*>(&(*out)[out_length]),
                       &padding) == 0) {
    LOGE("AesCbcKey::Encrypt: PKCS7 padding failure: %s",
         ERR_error_string(ERR_get_error(), NULL));
    return false;
  }

  out->resize(out_length + padding);
  return true;
}

RsaPublicKey::~RsaPublicKey() {
  if (key_ != NULL) {
    RSA_free(key_);
  }
}

bool RsaPublicKey::Init(const std::string& serialized_key) {

  if (serialized_key.empty()) {
    LOGE("RsaPublicKey::Init: no serialized key provided");
    return false;
  }

  BIO* bio = BIO_new_mem_buf(const_cast<char*>(serialized_key.data()),
                             serialized_key.size());
  if (bio == NULL) {
    LOGE("RsaPublicKey::Init: BIO_new_mem_buf returned NULL");
    return false;
  }
  key_ = d2i_RSAPublicKey_bio(bio, NULL);
  BIO_free(bio);

  if (key_ == NULL) {
    LOGE("RsaPublicKey::Init: RSA key deserialization failure: %s",
         ERR_error_string(ERR_get_error(), NULL));
    return false;
  }

  return true;
}

bool RsaPublicKey::Encrypt(const std::string& clear_message,
                           std::string* encrypted_message) {
  if (clear_message.empty()) {
    LOGE("RsaPublicKey::Encrypt: message to be encrypted is empty");
    return false;
  }
  if (encrypted_message == NULL) {
    LOGE("RsaPublicKey::Encrypt: no encrypt message buffer provided");
    return false;
  }
  if (key_ == NULL) {
    LOGE("RsaPublicKey::Encrypt: RSA key not initialized");
    return false;
  }

  int rsa_size = RSA_size(key_);
  if (static_cast<int>(clear_message.size()) >
      rsa_size - kRsaPkcs1OaepPaddingLength) {
    LOGE("RsaPublicKey::Encrypt: message too large to be encrypted (actual %d",
         " max allowed %d)", clear_message.size(),
         rsa_size - kRsaPkcs1OaepPaddingLength);
    return false;
  }
  encrypted_message->assign(rsa_size, 0);
  if (RSA_public_encrypt(
          clear_message.size(),
          const_cast<unsigned char*>(
              reinterpret_cast<const unsigned char*>(clear_message.data())),
          reinterpret_cast<unsigned char*>(&(*encrypted_message)[0]), key_,
          RSA_PKCS1_OAEP_PADDING) != rsa_size) {
    LOGE("RsaPublicKey::Encrypt: encrypt failure: %s",
         ERR_error_string(ERR_get_error(), NULL));
    return false;
  }
  return true;
}

bool RsaPublicKey::VerifySignature(const std::string& message,
                                   const std::string& signature) {
  if (key_ == NULL) {
    LOGE("RsaPublicKey::VerifySignature: RSA key not initialized");
    return false;
  }
  if (message.empty()) {
    LOGE("RsaPublicKey::VerifySignature: signed message is empty");
    return false;
  }

  int rsa_size = RSA_size(key_);
  if (static_cast<int>(signature.size()) != rsa_size) {
    LOGE(
        "RsaPublicKey::VerifySignature: message signature is of the wrong "
        "size (expected %d, actual %d)",
        rsa_size, signature.size());
    return false;
  }
  // Decrypt the signature.
  std::string padded_digest(signature.size(), 0);
  if (RSA_public_decrypt(
          signature.size(),
          const_cast<unsigned char*>(
              reinterpret_cast<const unsigned char*>(signature.data())),
          reinterpret_cast<unsigned char*>(&padded_digest[0]), key_,
          RSA_NO_PADDING) != rsa_size) {
    LOGE("RsaPublicKey::VerifySignature: RSA public decrypt failure: %s",
         ERR_error_string(ERR_get_error(), NULL));
    return false;
  }

  // Hash the message using SHA1.
  std::string message_digest(SHA_DIGEST_LENGTH, 0);
  SHA1(reinterpret_cast<const unsigned char*>(message.data()), message.size(),
       reinterpret_cast<unsigned char*>(&message_digest[0]));

  // Verify PSS padding.
  if (RSA_verify_PKCS1_PSS(
          key_, reinterpret_cast<const unsigned char*>(message_digest.data()),
          EVP_sha1(),
          reinterpret_cast<const unsigned char*>(padded_digest.data()),
          kPssSaltLength) == 0) {
    LOGE("RsaPublicKey::VerifySignature: RSA verify failure: %s",
         ERR_error_string(ERR_get_error(), NULL));
    return false;
  }

  return true;
}

}  // namespace wvcdm
