/*
 * Copyright (C) 2011 Google, Inc.  All Rights Reserved
 */

#define LOG_TAG "WVMExtractorImpl"
#include <utils/Log.h>
#include <cutils/qtaguid.h>
#include <cutils/properties.h>

#include "WVMExtractorImpl.h"
#include "WVMMediaSource.h"
#include "WVMFileSource.h"
#include "WVMInfoListener.h"
#include "WVMLogging.h"
#include "WVStreamControlAPI.h"
#include "media/stagefright/MediaErrors.h"
#include "media/stagefright/MediaDefs.h"
#include "drm/DrmManagerClient.h"
#include "drm/DrmConstraints.h"
#include "drm/DrmInfoEvent.h"
#include "AndroidHooks.h"

#define AES_BLOCK_SIZE 16

using namespace android;

static sp<DecryptHandle> sDecryptHandle;
static DrmManagerClient *sDrmManagerClient;

static void _cb1(char *data, unsigned long size)
{
    DrmBuffer buf(data, size);
    if (sDrmManagerClient != NULL) {
        sDrmManagerClient->initializeDecryptUnit(sDecryptHandle, 0, &buf);
    }

}

static int _cb2(char *in, char *out, int length, char *iv)
{
    int status = -1;

    if (sDrmManagerClient != NULL) {
        DrmBuffer encryptedDrmBuffer(in, length);
        DrmBuffer ivBuffer(iv, (iv? AES_BLOCK_SIZE: 0));

        DrmBuffer decryptedDrmBuffer(out, length);
        DrmBuffer *decryptedDrmBufferPtr = &decryptedDrmBuffer;

        char ivout[AES_BLOCK_SIZE];
        if (in && length) {
            memcpy(ivout, in + length - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
        }

        status = sDrmManagerClient->decrypt(sDecryptHandle, 0,
                                            &encryptedDrmBuffer, &decryptedDrmBufferPtr,
                                            &ivBuffer);

        if (iv) {
            memcpy(iv, ivout, AES_BLOCK_SIZE);
        }
    }

    return status;
}

namespace android {

// DLL entry - construct an extractor and return it
WVMLoadableExtractor *GetInstance(sp<DataSource> dataSource) {
    return new WVMExtractorImpl(dataSource);
}

bool IsWidevineMedia(const sp<DataSource>& dataSource) {
    String8 uri = dataSource->getUri();
    if (uri.getPathExtension() == ".m3u8" || uri.find(".m3u8?") != -1) {
        // can't sniff live streams - check for .m3u8 file extension
        return true;
    }

    ssize_t kSniffSize = 128 * 1024;
    char *buffer = new char[kSniffSize];
    bool result = false;

    if (buffer) {
        ssize_t bytesRead = dataSource->readAt(0, buffer, kSniffSize);
        if (bytesRead < kSniffSize) {
            ALOGV("IsWidevineMedia - insufficient data: %d", (int)bytesRead);
        } else {
            setenv("WV_SILENT", "true", 1);
            result = WV_IsWidevineMedia(buffer, kSniffSize);
        }
        delete[] buffer;
    }
    return result;
}



WVMExtractorImpl::WVMExtractorImpl(sp<DataSource> dataSource)
    : mFileMetaData(new MetaData()),
      mDataSource(dataSource),
      mClientContext(new ClientContext()),
      mHaveMetaData(false),
      mUseAdaptiveStreaming(false),
      mIsLiveStream(false),
      mCryptoInitialized(false),
      mSession(NULL),
      mDuration(0),
      mError(OK),
      mSetupStatus(OK)
{
    dataSource->getDrmInfo(sDecryptHandle, &sDrmManagerClient);

    //ALOGD("WVMExtractorImpl::WVMExtractorImpl: uniqueId = %d", sDrmManagerClient->mUniqueId);

    _ah006(android_printbuf);
    _ah002(_cb1);
    _ah004(_cb2);

    if (sDecryptHandle != NULL) {
        if (sDecryptHandle->status != RightsStatus::RIGHTS_VALID) {
            mSetupStatus = ERROR_DRM_NO_LICENSE;
        }
    } else {
        mSetupStatus = ERROR_DRM_NO_LICENSE;
    }

    // Set an info listener to handle messages from the drm plugin
    mInfoListener = new WVMInfoListener();

    sDrmManagerClient->setOnInfoListener(mInfoListener);
}

void WVMExtractorImpl::Initialize()
{
    //ALOGD("WVMExtractorImpl::Initialize(%d)\n", getAdaptiveStreamingMode());
    WVCredentials credentials;
    WVStatus result;

    if (mSetupStatus != OK) {
        setError(mSetupStatus);
        return;
    }

    if (mDataSource->getUri().size() > 0 && getAdaptiveStreamingMode()) {
        mIsLiveStream = (mDataSource->getUri().getPathExtension().find(".m3u8") == 0);
    }

    WVCallbacks callbacks;
    // The following memset is needed for 4.5.0 only, because WVCallbacks is a struct.
    memset( &callbacks, 0, sizeof(callbacks));
    callbacks.socketInfo = SocketInfoCallback;
#ifdef REQUIRE_SECURE_BUFFERS
    if (!mClientContext->getCryptoPluginMode()) {
        OEMCryptoResult res = OEMCrypto_Initialize();
        if (res == OEMCrypto_SUCCESS) {
            mCryptoInitialized = true;
        } else {
            ALOGE("Crypto initialize failed (%d)", res);
        }
    }

    if (!mIsLiveStream) {
        //ALOGD("WVMExtractorImpl::Initialize setting DecryptCallback\n");
        callbacks.decrypt = WVMMediaSource::DecryptCallback;
    }
#else
    if (!mIsLiveStream && mClientContext->getCryptoPluginMode()) {
        callbacks.decrypt = WVMMediaSource::DecryptCallback;
    }
#endif
    result = WV_Initialize(&callbacks);

    if (result != WV_Status_OK) {
        ALOGE("WV_Initialize returned status %d\n", result);
        mSetupStatus = ERROR_IO;
    } else {
        // Enable for debugging HTTP messages
        // WV_SetLogging(WV_Logging_HTTP);

        if (mDataSource->getUri().size() > 0 && getAdaptiveStreamingMode()) {
            // Use the URI - streaming case, only for widevine:// protocol
            result = WV_Setup(mSession, mDataSource->getUri().string(),
                              "RAW/RAW/RAW;destination=getdata", credentials,
                              WV_OutputFormat_ES, getStreamCacheSize(), mClientContext.get());
        } else {
            // No URI supplied or not adaptive, pull data from the stagefright data source.
            mFileSource = new WVMFileSource(mDataSource);
            result = WV_Setup(mSession, mFileSource.get(),
                              "RAW/RAW/RAW;destination=getdata", credentials,
                              WV_OutputFormat_ES, getStreamCacheSize(), mClientContext.get());
        }

        if (result != WV_Status_OK) {
            ALOGE("WV_Setup returned status %d in WVMMediaSource::start\n", result);
            mSetupStatus = ERROR_IO;
            WV_Teardown(mSession);
            mSession = NULL;
        } else {
            mInfoListener->setSession(mSession);
        }
    }

    if (mSetupStatus != OK) {
        setError(mSetupStatus);
    }

    WV_SetWarningToErrorMS(10000);
}

WVMExtractorImpl::~WVMExtractorImpl() {
}

// Release decrypt handle when media sources are destroyed
void WVMExtractorImpl::cleanup()
{
    if (sDecryptHandle.get()) {
        sDecryptHandle.clear();
    }
}

void WVMExtractorImpl::SocketInfoCallback(int fd, int closing, void *context)
{
    //ALOGD("WVMExtractorImpl::SocketInfoCallback(%d, %d, %p)", fd, closing, context);

    ClientContext *obj = (ClientContext *)context;

    if (!obj) {
        // Not an error, there are some cases where this is expected
        return;
    } else if (!obj->haveUID()) {
        ALOGW("SocketInfoCallback: UID not set!");
        return;
    }

    if (!closing) {
        uint32_t kTag = *(uint32_t *)"WVEX";
        int res = qtaguid_tagSocket(fd, kTag, obj->getUID());
        if (res != 0) {
            ALOGE("Failed tagging socket %d for uid %d (My UID=%d)", fd, obj->getUID(), geteuid());
        }
    } else {
        int res = qtaguid_untagSocket(fd);
        if (res != 0) {
            ALOGE("Failed untagging socket %d (My UID=%d)", fd, geteuid());
        }
    }
}


//
// Configure metadata for video and audio sources
//
status_t WVMExtractorImpl::readMetaData()
{
    if (mHaveMetaData) {
        return OK;
    }

    Initialize();

    if (mSetupStatus != OK) {
        return mSetupStatus;
    }

    // Get Video Configuration
    WVVideoType videoType;
    unsigned short videoStreamID;
    unsigned short videoProfile;
    unsigned short level;
    unsigned short width, height;
    float aspect, frameRate;
    unsigned long videoBitRate;

    WVStatus result = WV_Info_GetVideoConfiguration(mSession, &videoType, &videoStreamID,
                                                    &videoProfile, &level, &width, &height,
                                                    &aspect,  &frameRate, &videoBitRate);
    if (result != WV_Status_OK) {
        return ERROR_MALFORMED;
    }

    // Get Audio Configuration
    WVAudioType audioType;
    unsigned short audioStreamID;
    unsigned short audioProfile;
    unsigned short numChannels;
    unsigned long sampleRate;
    unsigned long audioBitRate;

    result = WV_Info_GetAudioConfiguration(mSession, &audioType, &audioStreamID, &audioProfile,
                                           &numChannels, &sampleRate, &audioBitRate);
    if (result != WV_Status_OK) {
        return ERROR_MALFORMED;
    }

    if (numChannels == 0) {
        ALOGD("numChannels is 0!");
        return ERROR_MALFORMED;
    }

    std::string durationString = WV_Info_GetDuration(mSession, "sec");
    if (durationString == "") {
        // We won't have a duration for live streams, and Stagefright doesn't seem to
        // have a way to represent that.  Give a default duration of 1 hour for now.
        if (mIsLiveStream) {
            durationString = "3600";
        } else {
            return ERROR_MALFORMED;
        }
    }

    mDuration = (int64_t)(strtod(durationString.c_str(), NULL) * 1000000);

    sp<MetaData> audioMetaData = new MetaData();
    sp<MetaData> videoMetaData = new MetaData();

    audioMetaData->setInt64(kKeyDuration, mDuration);
    videoMetaData->setInt64(kKeyDuration, mDuration);

    audioMetaData->setInt32(kKeyBitRate, audioBitRate);
    videoMetaData->setInt32(kKeyBitRate, videoBitRate);

    switch(videoType) {
    case WV_VideoType_H264:
        videoMetaData->setCString(kKeyMIMEType, MEDIA_MIMETYPE_VIDEO_AVC);
        break;
    default:
        ALOGE("Invalid WV video type %d, expected H264C\n", audioType);
        break;
    }

    switch(audioType) {
    case WV_AudioType_AAC:
        audioMetaData->setCString(kKeyMIMEType, MEDIA_MIMETYPE_AUDIO_AAC);
        break;
    default:
        ALOGE("Invalid WV audio type %d, expected AAC\n", audioType);
        break;
    }

    audioMetaData->setInt32(kKeyTrackID, audioStreamID);
    videoMetaData->setInt32(kKeyTrackID, videoStreamID);

    audioMetaData->setInt32(kKeyChannelCount, numChannels);
    audioMetaData->setInt32(kKeySampleRate, sampleRate);

    videoMetaData->setInt32(kKeyWidth, width);
    videoMetaData->setInt32(kKeyHeight, height);

    if (mIsLiveStream) {
        float scaleUsed;
        result = WV_Play(mSession, 1.0, &scaleUsed, "npt=now-");
        if (result != WV_Status_OK) {
            ALOGE("WV_Play for live stream setup failed: %d", result);
            return ERROR_IO;
        }
    }

    status_t status;

    status = readESDSMetaData(audioMetaData);
    if (status != OK) {
        return status;
    }

    if (mIsLiveStream) {
        result = WV_Pause(mSession, "");
        if (result != WV_Status_OK) {
            ALOGE("WV_Pause for live stream setup failed: %d", result);
        }
    }

    bool cryptoPluginMode = mClientContext->getCryptoPluginMode();

    mAudioSource = new WVMMediaSource(mSession, WV_EsSelector_Audio, audioMetaData,
                                      mIsLiveStream, cryptoPluginMode, false);
    mVideoSource = new WVMMediaSource(mSession, WV_EsSelector_Video, videoMetaData,
                                      mIsLiveStream, cryptoPluginMode, mCryptoInitialized);

    //  Since the WVExtractor goes away soon after this, we delegate ownership of some resources
    //  to the constructed media source
    if (mFileSource.get()) {
        mVideoSource->delegateFileSource(mFileSource);
    }

    mVideoSource->delegateDataSource(mDataSource);

    mClientContext->setAudioSource(mAudioSource);
    mClientContext->setVideoSource(mVideoSource);
    mVideoSource->delegateClientContext(mClientContext);

    mHaveMetaData = true;

    mInfoListener->configureHeartbeat();

    if (cryptoPluginMode) {
        // In crypto plugin mode, need to trigger the drm plugin to begin
        // license use on playback since the media player isn't involved.
        sDrmManagerClient->setPlaybackStatus(sDecryptHandle, Playback::START, 0);

#ifndef REQUIRE_SECURE_BUFFERS
        if (!mIsLiveStream) {
            // Get the content key for crypto plugin mode on L3 devices
            char keyBuffer[AES_BLOCK_SIZE];
            char nullBuffer[0];
            DrmBuffer nullDrmBuffer(nullBuffer, 0);
            DrmBuffer keyDrmBuffer(keyBuffer, sizeof(keyBuffer));
            DrmBuffer *keyDrmBufferPtr = &keyDrmBuffer;

            status_t status = sDrmManagerClient->decrypt(sDecryptHandle, 0, &nullDrmBuffer,
                                                         &keyDrmBufferPtr, &nullDrmBuffer);
            if (status != OK) {
                return status;
            }

            mVideoSource->SetCryptoPluginKey(keyBuffer);
            mAudioSource->SetCryptoPluginKey(keyBuffer);
        }
#endif
    }

    return OK;
}

status_t WVMExtractorImpl::readESDSMetaData(sp<MetaData> audioMetaData)
{
    WVStatus result;

    const unsigned char *config;
    unsigned long size;
    int limit = 500;
    do {
        size_t bytesRead;
        bool auStart, sync;
        unsigned long long dts, pts;
        unsigned char buf[1];
        size_t bufSize = 0;

        //
        // In order to get the codec config data, we need to have the WVMK
        // pull some audio data.  But we can't use it yet, so just request 0 bytes.
        //
        (void)WV_GetEsData(mSession, WV_EsSelector_Audio,  buf, bufSize,
                           bytesRead, auStart, dts, pts, sync);

        result = WV_Info_GetCodecConfig(mSession, WV_CodecConfigType_ESDS, config, size);
        if (result != WV_Status_OK) {
            usleep(10000);
        }
    } while (result == WV_Status_Warning_Not_Available && limit-- > 0);

    if (result != WV_Status_OK) {
        ALOGE("WV_Info_GetCodecConfig ESDS returned error %d\n", result);
        return ERROR_IO;
    }

#if 0
    char *filename = "/data/wvm/esds";
    FILE *f = fopen(filename, "w");
    if (!f) {
        ALOGD("Failed to open %s", filename);
    } else {
        fwrite(config, size, 1, f);
        fclose(f);
    }
#endif
    audioMetaData->setData(kKeyESDS, kTypeESDS, config, size);
    return OK;
}

size_t WVMExtractorImpl::countTracks() {
    status_t err;
    if ((err = readMetaData()) != OK) {
        setError(err);
        return 0;
    }

    return 2;  // 1 audio + 1 video
}

sp<MediaSource> WVMExtractorImpl::getTrack(size_t index)
{
    status_t err;
    if ((err = readMetaData()) != OK) {
        setError(err);
        return NULL;
    }

    sp<MediaSource> result;

    switch(index) {
    case 0:
        result = mVideoSource;
        break;
    case 1:
        result = mAudioSource;
        break;
    default:
        break;
    }
    return result;
}


sp<MetaData> WVMExtractorImpl::getTrackMetaData(size_t index, uint32_t flags)
{
    status_t err;
    if ((err = readMetaData()) != OK) {
        setError(err);
        return NULL;
    }

    sp<MetaData> result;
    switch(index) {
    case 0:
        if (mVideoSource != NULL) {
            result = mVideoSource->getFormat();
        }
        break;
    case 1:
        if (mAudioSource != NULL) {
            result = mAudioSource->getFormat();
        }
        break;
    default:
        break;
    }
    return result;
}

sp<MetaData> WVMExtractorImpl::getMetaData() {
    mFileMetaData->setCString(kKeyMIMEType, "video/wvm");
    return mFileMetaData;
}

int64_t WVMExtractorImpl::getCachedDurationUs(status_t *finalStatus) {
    const size_t kMaxEncodedRates = 32;
    unsigned long encodedRates[kMaxEncodedRates];
    size_t ratesReturned, currentTrack;
    unsigned long minRate = ULONG_MAX;
    unsigned long bandwidth = ULONG_MAX;

    WVStatus status = WV_Info_GetAdaptiveBitrates(mSession, encodedRates, kMaxEncodedRates,
                                                  &ratesReturned, &currentTrack);
    if (status == WV_Status_OK) {
        if (currentTrack != kMaxEncodedRates && ratesReturned != 0) {
            for (size_t i = 0; i < ratesReturned; i++) {
                if (encodedRates[i] < minRate) {
                    minRate = encodedRates[i];
                }
            }

            WV_Info_CurrentBandwidth(mSession, &bandwidth);

            // Log the current adaptive rate every 5 seconds
            time_t now = time(0);
            static time_t lastLogTime = now;
            if (now > lastLogTime + 5) {
                lastLogTime = now;
                ALOGI("using adaptive track #%d, rate=%ld, bandwidth=%ld\n",
                      currentTrack, encodedRates[currentTrack], bandwidth);
            }
        }
    }

    uint64_t durationUs = 0;
    float secondsBuffered;
    status = WV_Info_TimeBuffered(mSession, &secondsBuffered);

    //
    // As long as the bandwidth is greater than the min bitrate, don't
    // need to consider rebuffering so return a buffered time greater
    // than the low water mark.  This provides fast startup when the
    // network speed is good and rebuffering when it is not.
    //
    if (bandwidth != ULONG_MAX && minRate != ULONG_MAX && bandwidth >= minRate) {
        //ALOGD("Bandwidth %ld is sufficient for lowest rate %ld, override buffered time", bandwidth, minRate);
        durationUs = 10000000LL;
    } else {
        unsigned long kScaleFactor = 2; // scale to cached duration to tune watermark levels
        durationUs = (uint64_t)(secondsBuffered * 1000000LL * kScaleFactor);
        //ALOGD("Bandwidth %ld is too low for lowest rate %ld, use buffered time %lld", bandwidth, minRate, durationUs);
    }

    if (status == WV_Status_End_Of_Media) {
        *finalStatus = ERROR_END_OF_STREAM;
    } else if (status != WV_Status_OK) {
        *finalStatus = ERROR_IO;
    } else {
        if (mIsLiveStream) {
            *finalStatus = ERROR_END_OF_STREAM;
        } else {
            *finalStatus = OK;

            int64_t current_time = 0;  // usec.
            if (mVideoSource != NULL) {
                current_time = mVideoSource->getTime();
            } else {
                ALOGV("getCachedDurationUs: current_time not yet valid.");
            }

            // ALOGD("current_time=%.2f,  duration %.2f, delta = %.2f, buffered=%.2f",
            //      current_time/1e6, mDuration/1e6,
            //      (mDuration - current_time )/1e6, time_buffered);

            // If we are less than 10 seconds from end, report we are at the end.
            if (mDuration > 0 && mDuration - current_time < 10000000) {
                *finalStatus = ERROR_END_OF_STREAM;
            }
        }
    }
    return durationUs;
}

status_t WVMExtractorImpl::getEstimatedBandwidthKbps(int32_t *kbps)
{
    status_t err = UNKNOWN_ERROR;
    unsigned long bandwidth;
    WVStatus status = WV_Info_CurrentBandwidth(mSession, &bandwidth);
    if (status == WV_Status_OK) {
        *kbps = bandwidth / 1024;
        err = OK;
    } else {
        ALOGV("WV_Info_CurrentBandwidth failed: %d", status);
    }
    return err;
}

void WVMExtractorImpl::setAdaptiveStreamingMode(bool adaptive)
{
    //ALOGD("WVMExtractorImpl::setAdaptiveStreamingMode(%d)", adaptive);
    mUseAdaptiveStreaming = adaptive;
}

bool WVMExtractorImpl::getAdaptiveStreamingMode() const
{
    //ALOGD("WVMExtractorImpl::getAdaptiveStreamingMode - %d", mUseAdaptiveStreaming);
    return mUseAdaptiveStreaming;
}

void WVMExtractorImpl::setCryptoPluginMode(bool cryptoPluginMode)
{
    //ALOGD("WVMExtractorImpl::setCryptoPluginMode(%d)", cryptoPluginMode);
    mClientContext->setCryptoPluginMode(cryptoPluginMode);
}

void WVMExtractorImpl::setUID(uid_t uid)
{
    //ALOGD("WVMExtractorImpl::setUID(%d)", (uint32_t)uid);
    mClientContext->setUID(uid);
}

size_t WVMExtractorImpl::getStreamCacheSize() const
{
    char value[PROPERTY_VALUE_MAX];

    if (property_get("ro.com.widevine.cachesize", value, NULL) > 0) {
        return atol(value);
    } else {
        return kDefaultStreamCacheSize;
    }
}

status_t WVMExtractorImpl::getError() {
    Mutex::Autolock autoLock(mLock);

    status_t err = mError;
    mError = OK;

    //
    // MediaPlayer.java documents these MEDIA_ERROR codes for applications:
    // MEDIA_ERROR_UNKNOWN, MEDIA_ERROR_SERVER_DIED, MEDIA_ERROR_IO,
    // MEDIA_ERROR_MALFORMED, MEDIA_ERROR_UNSUPPORTED and MEDIA_ERROR_TIMED_OUT.
    // In order to not change the behavior of WVMExtractorImpl.cpp,
    // we return all ERROR_ codes used by the WVMExtractor in addition to
    // those documented in MediaPlayer.java.
    //
    if (err == ERROR_DRM_NO_LICENSE || err == ERROR_END_OF_STREAM ||
        err == ERROR_IO || err == ERROR_MALFORMED || err == OK ||
        err == ERROR_UNSUPPORTED) {
        return err;
    } else {
        return UNKNOWN_ERROR;
    }
}

void WVMExtractorImpl::setError(status_t err) {
    Mutex::Autolock autoLock(mLock);

    mError = err;
}

} // namespace android
