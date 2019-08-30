/*
 * Copyright (C) 2011 Google, Inc.  All Rights Reserved
 */

#ifndef WVMEXTRACTOR_H_

#define WVMEXTRACTOR_H_

#include "AndroidConfig.h"
#include "WVStreamControlAPI.h"
#include "WVMInfoListener.h"
#include "WVMExtractor.h"
#include <media/stagefright/DataSource.h>
#include <utils/RefBase.h>

// DLL entry - given a data source, instantiate a WVMExtractor object

namespace android {

WVMLoadableExtractor *GetInstance(sp<DataSource> dataSource);
bool IsWidevineMedia(const sp<DataSource>& dataSource);

class WVMMediaSource;
class WVMFileSource;

class WVMExtractorImpl : public WVMLoadableExtractor {
public:
    WVMExtractorImpl(sp<DataSource> dataSource);

    virtual size_t countTracks();
    virtual sp<MediaSource> getTrack(size_t index);
    virtual sp<MetaData> getTrackMetaData(size_t index, uint32_t flags);

    virtual sp<MetaData> getMetaData();
    virtual int64_t getCachedDurationUs(status_t *finalStatus);
    virtual status_t getEstimatedBandwidthKbps(int32_t *kbps);

    virtual void setAdaptiveStreamingMode(bool adaptive);
    bool getAdaptiveStreamingMode() const;

    //
    // if in CryptoPlugin mode, the extractor doesn't decrypt,
    // it just accumulates the ranges of data requiring decryption
    // into the MediaBuffer's metadata, the decryption happens
    // later via the CryptoPlugin
    //
    virtual void setCryptoPluginMode(bool cryptoPluginMode);

    virtual void setUID(uid_t uid);

    static void SocketInfoCallback(int fd, int op, void *context);
    static void cleanup();

    status_t getError() ;

    void setError(status_t err);

protected:
    virtual ~WVMExtractorImpl();
    void Initialize();

private:
    Mutex mLock;

    status_t readAVCCMetaData(sp<MetaData> videoMetaData);
    status_t readESDSMetaData(sp<MetaData> audioMetaData);

    sp<WVMMediaSource> mAudioSource;
    sp<WVMMediaSource> mVideoSource;
    sp<MetaData> mFileMetaData;
    sp<WVMFileSource> mFileSource;
    sp<DataSource> mDataSource;
    sp<WVMInfoListener> mInfoListener;
    sp<ClientContext> mClientContext;

    bool mHaveMetaData;
    bool mUseAdaptiveStreaming;
    bool mIsLiveStream;
    bool mCryptoInitialized;

    WVSession *mSession;

    int64_t mDuration;  // usec.

    status_t mError;

    status_t mSetupStatus;

    status_t readMetaData();

    size_t getStreamCacheSize() const;

    const static size_t kDefaultStreamCacheSize = 10 * 1024 * 1024;

    WVMExtractorImpl(const WVMExtractorImpl &);
    WVMExtractorImpl &operator=(const WVMExtractorImpl &);
};

}  // namespace android

#endif  // WVMEXTRACTOR_H_
