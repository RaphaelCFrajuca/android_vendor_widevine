/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//#define LOG_NDEBUG 0
#define LOG_TAG "wv_crypto_plugin"
#include <cutils/properties.h>
#include <utils/Log.h>
#include <string.h>
#include <openssl/md5.h>

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/hexdump.h>
#include <media/stagefright/MediaErrors.h>

#include "WVCryptoPlugin.h"

#ifdef REQUIRE_SECURE_BUFFERS
#include <OEMCrypto_L1.h>
#endif

android::CryptoFactory *createCryptoFactory() {
    return new android::WVCryptoFactory;
}

namespace android {

// static
const uint8_t WVCryptoFactory::kUUIDWidevine[16] = {
    0xED,0xEF,0x8B,0xA9,0x79,0xD6,0x4A,0xCE,
    0xA3,0xC8,0x27,0xDC,0xD5,0x1D,0x21,0xED
};

WVCryptoPlugin::WVCryptoPlugin(const void *data, size_t size)
    : mInitCheck(NO_INIT)
{
    // not using data at this time, require
    // size to be zero.
    if (size > 0) {
        mInitCheck = -EINVAL;
    } else {
        mInitCheck = OK;

#ifdef REQUIRE_SECURE_BUFFERS
        OEMCryptoResult res = OEMCrypto_Initialize();
        if (res != OEMCrypto_SUCCESS) {
            ALOGE("OEMCrypto_Initialize failed: %d", res);
            mInitCheck = -EINVAL;
        }
#endif
    }
}

WVCryptoPlugin::~WVCryptoPlugin() {

#ifdef REQUIRE_SECURE_BUFFERS
    if (mInitCheck == OK) {
        OEMCryptoResult res = OEMCrypto_Terminate();
        if (res != OEMCrypto_SUCCESS) {
            ALOGW("OEMCrypto_Terminate failed: %d", res);
        }
    }
#endif
}

status_t WVCryptoPlugin::initCheck() const {
    return mInitCheck;
}

bool WVCryptoPlugin::requiresSecureDecoderComponent(const char *mime) const {
#ifdef REQUIRE_SECURE_BUFFERS
    return !strncasecmp(mime, "video/", 6);
#else
    return false;
#endif
}

// Returns negative values for error code and
// positive values for the size of decrypted data, which can be larger
// than the input length.
ssize_t WVCryptoPlugin::decrypt(
        bool secure,
        const uint8_t key[16],
        const uint8_t iv[16],
        Mode mode,
        const void *srcPtr,
        const SubSample *subSamples, size_t numSubSamples,
        void *dstPtr,
        AString *errorDetailMsg) {
    Mutex::Autolock autoLock(mLock);


    CHECK(mode == kMode_Unencrypted || mode == kMode_AES_WV);

    size_t srcOffset = 0;
    size_t dstOffset = 0;
    for (size_t i = 0; i < numSubSamples; ++i) {
        const SubSample &ss = subSamples[i];

        size_t srcSize;

        if (mode == kMode_Unencrypted) {
            srcSize = ss.mNumBytesOfClearData;
            CHECK_EQ(ss.mNumBytesOfEncryptedData, 0u);
        } else {
            CHECK_EQ(ss.mNumBytesOfClearData, 0u);
            srcSize = ss.mNumBytesOfEncryptedData;
        }

        //ALOGD("size[%d]=%d", i, srcSize);
        if (srcSize == 0) {
            continue;   // segment size is zero, do not call decrypt
        }

#ifdef REQUIRE_SECURE_BUFFERS
        // decrypt using OEMCrypto API, used for L1 devices
        OEMCrypto_UINT32 dstSize = srcSize;

        OEMCryptoResult res;

        OEMCrypto_UINT8 _iv[16];
        const OEMCrypto_UINT8 *iv = NULL;

        if (mode != kMode_Unencrypted) {
            memset(_iv, 0, sizeof(_iv));
            iv = _iv;
        }

        if (secure) {
            //ALOGD("calling DecryptVideo, size=%d", srcSize);
            res = OEMCrypto_DecryptVideo(
                    iv,
                    (const OEMCrypto_UINT8 *)srcPtr + srcOffset,
                    srcSize,
                    (OEMCrypto_UINT32)dstPtr,
                    dstOffset,
                    &dstSize);
        } else {
            //ALOGD("calling DecryptAudio: size=%d", srcSize);
            res = OEMCrypto_DecryptAudio(
                    iv,
                    (const OEMCrypto_UINT8 *)srcPtr + srcOffset,
                    srcSize,
                    (OEMCrypto_UINT8 *)dstPtr + dstOffset,
                    &dstSize);
        }

        if (res != OEMCrypto_SUCCESS) {
            ALOGE("decrypt result: %d", res);
            return -EINVAL;
        }

        dstOffset += dstSize;
#else
        if (mode == kMode_Unencrypted) {
            memcpy((char *)dstPtr + dstOffset, (char *)srcPtr + srcOffset, srcSize);
        } else {
            status_t status = decryptSW(key, (uint8_t *)dstPtr + dstOffset,
                                        (const uint8_t *)srcPtr + srcOffset, srcSize);
            if (status != OK) {
                ALOGE("decryptSW returned %d", status);
                return status;
            }
        }

        dstOffset += srcSize;
#endif
        srcOffset += srcSize;
    } // for each subsample

    return static_cast<ssize_t>(dstOffset);
}

// SW AES CTS decrypt, used only for L3 devices
status_t WVCryptoPlugin::decryptSW(const uint8_t *key, uint8_t *out,
                                   const uint8_t *in, size_t length)
{
#ifndef REQUIRE_SECURE_BUFFERS
    unsigned char iv[kAES128BlockSize] = {0};

    if (memcmp(key, mEncKey, sizeof(mEncKey)) != 0) {
        // key has changed, recompute mAesKey from key
        uint8_t hash[MD5_DIGEST_LENGTH];
        char value[PROPERTY_VALUE_MAX] = {0};
        char seed[] = "34985woeirsdlkfjxc";

        property_get("ro.serialno", value, NULL);

        MD5_CTX ctx;
        MD5_Init(&ctx);
        MD5_Update(&ctx, (uint8_t *)seed, sizeof(seed));
        MD5_Update(&ctx, (uint8_t *)value, strlen(value));
        MD5_Final(hash, &ctx);

        AES_KEY aesKey;
        if (AES_set_decrypt_key(hash, sizeof(hash) * 8, &aesKey) == 0) {
            uint8_t clearKey[kAES128BlockSize];
            AES_ecb_encrypt(key, clearKey, &aesKey, 0);

            if (AES_set_decrypt_key(clearKey, sizeof(hash) * 8, &mAesKey) == 0) {
                memcpy(mEncKey, key, sizeof(mEncKey));
            } else {
                return -EINVAL;
            }
        } else {
            return -EINVAL;
        }
    }

    size_t k, r = length % kAES128BlockSize;

    if (r) {
        k = length - r - kAES128BlockSize;
    } else {
        k = length;
    }

    AES_cbc_encrypt(in, out, k, &mAesKey, iv, 0);

    if (r) {
        // cipher text stealing - Schneier Figure 9.5 p 196
        unsigned char peniv[kAES128BlockSize] = {0};
        memcpy(peniv, in + k + kAES128BlockSize, r);

        AES_cbc_encrypt(in + k, out + k, kAES128BlockSize, &mAesKey, peniv, 0);

        // exchange the final plaintext and ciphertext
        for (size_t i = 0; i < r; i++) {
            *(out + k + kAES128BlockSize + i) = *(out + k + i);
            *(out + k + i) = *(in + k + kAES128BlockSize + i);
        }
        AES_cbc_encrypt(out + k, out + k, kAES128BlockSize, &mAesKey, iv, 0);
    }
#endif
    return OK;
}

}  // namespace android

