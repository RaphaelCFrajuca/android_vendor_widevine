//
// Copyright 2013 Google Inc. All Rights Reserved.
//

//#define LOG_NDEBUG 0
#define LOG_TAG "WVCdm"
#include <utils/Log.h>

#include "WVCryptoPlugin.h"

#include <endian.h>
#include <string.h>
#include <string>
#include <vector>

#include "mapErrors-inl.h"
#include "media/stagefright/MediaErrors.h"
#include "OEMCryptoCENC.h"
#include "openssl/sha.h"
#include "utils/Errors.h"
#include "utils/String8.h"
#include "wv_cdm_constants.h"
#include "WVErrors.h"

namespace wvdrm {

using namespace android;
using namespace std;
using namespace wvcdm;

WVCryptoPlugin::WVCryptoPlugin(const void* data, size_t size,
                               WvContentDecryptionModule* cdm)
  : mCDM(cdm),
    mTestMode(false),
    mSessionId(configureTestMode(data, size)) {}

wvcdm::CdmSessionId WVCryptoPlugin::configureTestMode(const void* data,
                                                      size_t size) {
  wvcdm::CdmSessionId sessionId(static_cast<const char *>(data), size);
  size_t index = sessionId.find("test_mode");
  if (index != string::npos) {
      sessionId = sessionId.substr(0, index);
      mTestMode = true;
  }
  return sessionId;
}

bool WVCryptoPlugin::requiresSecureDecoderComponent(const char* mime) const {
  if (!strncasecmp(mime, "video/", 6)) {
    // Type is video, so query CDM to see if we require a secure decoder.
    CdmQueryMap status;

    CdmResponseType res = mCDM->QuerySessionStatus(mSessionId, &status);

    if (!isCdmResponseTypeSuccess(res)) {
      ALOGE("Error querying CDM status: %u", res);
      return false;
    }

    return status[QUERY_KEY_SECURITY_LEVEL] == QUERY_VALUE_SECURITY_LEVEL_L1;
  } else {
    // Type is not video, so never require a secure decoder.
    return false;
  }
}

// Returns negative values for error code and
// positive values for the size of decrypted data.  In theory, the output size
// can be larger than the input size, but in practice this should never happen
// for AES-CTR.
ssize_t WVCryptoPlugin::decrypt(bool secure, const uint8_t key[KEY_ID_SIZE],
                                const uint8_t iv[KEY_IV_SIZE], Mode mode,
                                const void* srcPtr, const SubSample* subSamples,
                                size_t numSubSamples, void* dstPtr,
                                AString* errorDetailMsg) {
  if (mode != kMode_Unencrypted && mode != kMode_AES_CTR) {
    errorDetailMsg->setTo("Encryption mode is not supported by Widevine CDM.");
    return kErrorUnsupportedCrypto;
  }

  // Convert parameters to the form the CDM wishes to consume them in.
  const KeyId keyId(reinterpret_cast<const char*>(key), KEY_ID_SIZE);
  vector<uint8_t> ivVector(iv, iv + KEY_IV_SIZE);
  const uint8_t* const source = static_cast<const uint8_t*>(srcPtr);
  uint8_t* const dest = static_cast<uint8_t*>(dstPtr);

  // Calculate the output buffer size
  size_t destSize = 0;
  for (size_t i = 0; i < numSubSamples; i++) {
    const SubSample &subSample = subSamples[i];
    destSize += subSample.mNumBytesOfClearData;
    destSize += subSample.mNumBytesOfEncryptedData;
  }

  // Set up the decrypt params that do not vary.
  CdmDecryptionParameters params = CdmDecryptionParameters();
  params.is_secure = secure;
  params.key_id = &keyId;
  params.iv = &ivVector;
  params.decrypt_buffer = dest;
  params.decrypt_buffer_length = destSize;

  // Iterate through subsamples, sending them to the CDM serially.
  size_t offset = 0;
  static const size_t kAESBlockSize = 16;
  size_t blockOffset = 0;

  for (size_t i = 0; i < numSubSamples; ++i) {
    const SubSample &subSample = subSamples[i];

    if (mode == kMode_Unencrypted && subSample.mNumBytesOfEncryptedData != 0) {
      errorDetailMsg->setTo("Encrypted subsamples found in allegedly "
                            "unencrypted data.");
      return kErrorExpectedUnencrypted;
    }

    // Calculate any flags that apply to this subsample's parts.
    uint8_t clearFlags = 0;
    uint8_t encryptedFlags = 0;

    // If this is the first subsample…
    if (i == 0) {
      // …add OEMCrypto_FirstSubsample to the first part that is present.
      if (subSample.mNumBytesOfClearData != 0) {
        clearFlags = clearFlags | OEMCrypto_FirstSubsample;
      } else {
        encryptedFlags = encryptedFlags | OEMCrypto_FirstSubsample;
      }
    }
    // If this is the last subsample…
    if (i == numSubSamples - 1) {
      // …add OEMCrypto_LastSubsample to the last part that is present
      if (subSample.mNumBytesOfEncryptedData != 0) {
        encryptedFlags = encryptedFlags | OEMCrypto_LastSubsample;
      } else {
        clearFlags = clearFlags | OEMCrypto_LastSubsample;
      }
    }

    // "Decrypt" any unencrypted data.  Per the ISO-CENC standard, clear data
    // comes before encrypted data.
    if (subSample.mNumBytesOfClearData != 0) {
      params.is_encrypted = false;
      params.encrypt_buffer = source + offset;
      params.encrypt_length = subSample.mNumBytesOfClearData;
      params.block_offset = 0;
      params.decrypt_buffer_offset = offset;
      params.subsample_flags = clearFlags;

      CdmResponseType res = mCDM->Decrypt(mSessionId, params);

      if (!isCdmResponseTypeSuccess(res)) {
        ALOGE("Decrypt error result in session %s during unencrypted block: %d",
              mSessionId.c_str(), res);
        errorDetailMsg->setTo("Error decrypting data.");
        if (res == wvcdm::INSUFFICIENT_CRYPTO_RESOURCES ||
            res == wvcdm::NEED_KEY) {
          // This error is actionable by the app and should be passed up.
          return mapCdmResponseType(res);
        } else {
          // Swallow the specifics of other errors to obscure decrypt internals.
          return kErrorCDMGeneric;
        }
      }

      offset += subSample.mNumBytesOfClearData;
    }

    // Decrypt any encrypted data.  Per the ISO-CENC standard, encrypted data
    // comes after clear data.
    if (subSample.mNumBytesOfEncryptedData != 0) {
      params.is_encrypted = true;
      params.encrypt_buffer = source + offset;
      params.encrypt_length = subSample.mNumBytesOfEncryptedData;
      params.block_offset = blockOffset;
      params.decrypt_buffer_offset = offset;
      params.subsample_flags = encryptedFlags;

      CdmResponseType res = mCDM->Decrypt(mSessionId, params);

      if (!isCdmResponseTypeSuccess(res)) {
        ALOGE("Decrypt error result in session %s during encrypted block: %d",
              mSessionId.c_str(), res);
        errorDetailMsg->setTo("Error decrypting data.");
        if (res == wvcdm::INSUFFICIENT_CRYPTO_RESOURCES ||
            res == wvcdm::NEED_KEY) {
          // This error is actionable by the app and should be passed up.
          return mapCdmResponseType(res);
        } else {
          // Swallow the specifics of other errors to obscure decrypt internals.
          return kErrorCDMGeneric;
        }
      }

      offset += subSample.mNumBytesOfEncryptedData;

      blockOffset += subSample.mNumBytesOfEncryptedData;
      incrementIV(blockOffset / kAESBlockSize, &ivVector);
      blockOffset %= kAESBlockSize;
    }
  }

  // In test mode, we return an error that causes a detailed error
  // message string containing a SHA256 hash of the decrypted data
  // to get passed to the java app via CryptoException.  The test app
  // can then use the hash to verify that decryption was successful.

  if (mTestMode) {
      if (secure) {
          // can't access data in secure mode
          errorDetailMsg->setTo("secure");
      } else {
          SHA256_CTX ctx;
          uint8_t digest[SHA256_DIGEST_LENGTH];
          SHA256_Init(&ctx);
          SHA256_Update(&ctx, dstPtr, offset);
          SHA256_Final(digest, &ctx);
          String8 buf;
          for (size_t i = 0; i < sizeof(digest); i++) {
              buf.appendFormat("%02x", digest[i]);
          }
          errorDetailMsg->setTo(buf.string());
      }

      return kErrorTestMode;
  }


  return static_cast<ssize_t>(offset);
}

void WVCryptoPlugin::incrementIV(uint64_t increaseBy, vector<uint8_t>* ivPtr) {
  vector<uint8_t>& iv = *ivPtr;
  uint64_t* counterBuffer = reinterpret_cast<uint64_t*>(&iv[8]);
  (*counterBuffer) = htonq(ntohq(*counterBuffer) + increaseBy);
}

}  // namespace wvdrm
