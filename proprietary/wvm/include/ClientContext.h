/*
 * Copyright (C) 2011 Google, Inc.  All Rights Reserved
 */

#ifndef CLIENTCONTEXT_H_
#define CLIENTCONTEXT_H_

#include <utils/RefBase.h>
#include <media/stagefright/foundation/ABase.h>

namespace android {

    class WVMMediaSource;

    class ClientContext : public RefBase {
    public:
        ClientContext() : mUIDIsSet(false), mCryptoPluginMode(false) {}

        void setUID(uid_t uid) { mUID = uid; mUIDIsSet = true; }
        uid_t getUID() const { return mUID; }
        bool haveUID() const { return mUIDIsSet; }

        void setCryptoPluginMode(bool cryptoPluginMode) { mCryptoPluginMode = cryptoPluginMode; }
        bool getCryptoPluginMode() const { return mCryptoPluginMode; }

        void setAudioSource(sp<WVMMediaSource> const &audioSource) { mAudioSource = audioSource; }
        void setVideoSource(sp<WVMMediaSource> const &videoSource) { mVideoSource = videoSource; }

        sp<WVMMediaSource> getAudioSource() const { return mAudioSource.promote(); }
        sp<WVMMediaSource> getVideoSource() const { return mVideoSource.promote(); }

    private:
        bool mUIDIsSet;;
        uid_t mUID;

        bool mCryptoPluginMode;

        wp<WVMMediaSource> mAudioSource;
        wp<WVMMediaSource> mVideoSource;

        DISALLOW_EVIL_CONSTRUCTORS(ClientContext);
    };
};

#endif

