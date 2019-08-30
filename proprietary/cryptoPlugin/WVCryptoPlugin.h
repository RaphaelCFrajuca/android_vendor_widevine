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

#ifndef WV_CRYPTO_PLUGIN_H_

#define WV_CRYPTO_PLUGIN_H_

#include <media/hardware/CryptoAPI.h>
#include <utils/threads.h>
#include <openssl/aes.h>

namespace android {

struct WVCryptoPlugin : public CryptoPlugin {
    WVCryptoPlugin(const void *data, size_t size);
    virtual ~WVCryptoPlugin();

    const static size_t kAES128BlockSize = 16;

    status_t initCheck() const;

    virtual bool requiresSecureDecoderComponent(const char *mime) const;

    virtual ssize_t decrypt(
            bool secure,
            const uint8_t key[kAES128BlockSize],
            const uint8_t iv[kAES128BlockSize],
            Mode mode,
            const void *srcPtr,
            const SubSample *subSamples, size_t numSubSamples,
            void *dstPtr,
            AString *errorDetailMsg);

private:
    status_t decryptSW(const uint8_t *key, uint8_t *out, const uint8_t *in, size_t length);

    Mutex mLock;

    status_t mInitCheck;
    AES_KEY mAesKey;
    uint8_t mEncKey[kAES128BlockSize];

    WVCryptoPlugin(const WVCryptoPlugin &);
    WVCryptoPlugin &operator=(const WVCryptoPlugin &);
};

struct WVCryptoFactory : public CryptoFactory {
    static const uint8_t kUUIDWidevine[16];

    virtual bool isCryptoSchemeSupported(
            const uint8_t uuid[16]) const {
        return !memcmp(uuid, kUUIDWidevine, 16);
    }

    virtual status_t createPlugin(
            const uint8_t uuid[16], const void *data, size_t size,
            CryptoPlugin **out) {
        *out = NULL;

        if (memcmp(uuid, kUUIDWidevine, 16)) {
            return -ENOENT;
        }

        WVCryptoPlugin *plugin = new WVCryptoPlugin(data, size);

        status_t err;
        if ((err = plugin->initCheck()) != OK) {
            delete plugin;
            plugin = NULL;

            return err;
        }

        *out = plugin;

        return OK;
    }
};

}  // namespace android

#endif // WV_CRYPTO_PLUGIN_H_

