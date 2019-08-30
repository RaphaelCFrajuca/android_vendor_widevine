/*
 * Copyright (C) 2011 Google, Inc.  All Rights Reserved
 */


#ifndef WVMMEDIA_SOURCE_H_
#define WVMMEDIA_SOURCE_H_

#include "AndroidConfig.h"
#include "WVStreamControlAPI.h"
#include <media/stagefright/DataSource.h>
#include <media/stagefright/MediaSource.h>
#include <media/stagefright/MetaData.h>
#include <media/stagefright/MediaBufferGroup.h>
#include <utils/RefBase.h>
#include "ClientContext.h"
#ifdef REQUIRE_SECURE_BUFFERS
#include "OEMCrypto_L1.h"
#endif


namespace android {

class WVMFileSource;

class WVMMediaSource : public MediaSource {
public:
    WVMMediaSource(WVSession *session, WVEsSelector esSelector,
                   const sp<MetaData> &metaData, bool isLive,
                   bool cryptoPluginMode, bool cryptoInitialized);

    void delegateFileSource(sp<WVMFileSource> fileSource);
    void delegateDataSource(sp<DataSource> dataSource);
    void delegateClientContext(sp<ClientContext> context);

    virtual status_t start(MetaData *params = NULL);
    virtual status_t stop();

    virtual sp<MetaData> getFormat();

    virtual status_t setBuffers(const Vector<MediaBuffer *> &buffers);
    virtual status_t read(MediaBuffer **buffer, const ReadOptions *options = NULL);

    void addEncryptedSize(size_t size) { mEncryptedSizes.push_back(size); }
    void addClearSize(size_t size) { mClearSizes.push_back(size); }

    static int sLastError;

    int64_t getTime() { return mKeyTime; };  // usec.

    static const int kCryptoBlockSize = 16;

    class DecryptContext {
    public:
        void Initialize(MediaBuffer *mediaBuf) {
            mMediaBuf = mediaBuf;
            mOffset = 0;
            memset(mIV, 0, sizeof(mIV));
        }
        MediaBuffer *mMediaBuf;
        size_t mOffset;
        unsigned char mIV[kCryptoBlockSize];
    };

    static void DecryptCallback(WVEsSelector esType, void* input, void* output, size_t length,
                                int key, void *context);
    DecryptContext& getDecryptContext() { return mDecryptContext; }

    void SetCryptoPluginKey(const char key[kCryptoBlockSize]) {
        memcpy(mCryptoPluginKey, key, sizeof(mCryptoPluginKey));
    }

private:
    DecryptContext mDecryptContext;

protected:
    virtual ~WVMMediaSource();

private:
    Mutex mLock;
    static int64_t sLastSeekTimeUs;

    WVSession *mSession;
    WVEsSelector mESSelector;  // indicates audio vs. video

    sp<MetaData> mTrackMetaData;

    bool mStarted;
    bool mLogOnce;
    bool mIsLiveStream;
    bool mNewSegment;
    bool mCryptoInitialized;
    bool mStripADTS;
    bool mCryptoPluginMode;

    MediaBufferGroup *mGroup;

    int64_t mKeyTime;
    unsigned long long mDts;
    unsigned long long mPts;

    sp<WVMFileSource> mFileSource;
    sp<DataSource> mDataSource;
    sp<ClientContext> mClientContext;

    Vector<size_t> mEncryptedSizes;
    Vector<size_t> mClearSizes;
    char mCryptoPluginKey[kCryptoBlockSize];

    void allocBufferGroup();

    WVMMediaSource(const WVMMediaSource &);
    WVMMediaSource &operator=(const WVMMediaSource &);
};

}  // namespace android

#endif // WVMMEDIA_SOURCE_H_
