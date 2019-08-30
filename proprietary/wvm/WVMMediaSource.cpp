/*
 * Copyright (C) 2011 Google, Inc.  All Rights Reserved
 */

#define LOG_TAG "WVMMediaSource"
#include <utils/Log.h>

#include "WVMMediaSource.h"
#include "WVMFileSource.h"
#include "WVMExtractorImpl.h"
#include "ClientContext.h"
#include "media/stagefright/foundation/ADebug.h"
#include "media/stagefright/MediaErrors.h"
#include "media/stagefright/MediaDefs.h"
#include "media/stagefright/MetaData.h"
#include "media/hardware/CryptoAPI.h"
#include "AndroidHooks.h"

namespace android {

static void _cb(int code)
{
    WVMMediaSource::sLastError = (status_t)code;
}

status_t WVMMediaSource::sLastError = NO_ERROR;
int64_t WVMMediaSource::sLastSeekTimeUs = -1;

WVMMediaSource::WVMMediaSource(WVSession *session, WVEsSelector esSelector,
                               const sp<MetaData> &metaData, bool isLive,
                               bool cryptoPluginMode, bool cryptoInitialized)
    : mSession(session),
      mESSelector(esSelector),
      mTrackMetaData(metaData),
      mStarted(false),
      mIsLiveStream(isLive),
      mNewSegment(false),
      mCryptoInitialized(cryptoInitialized),
      mStripADTS(false),
      mCryptoPluginMode(cryptoPluginMode),
      mGroup(NULL),
      mKeyTime(0),
      mDts(0),
      mPts(0)
{
    _ah010(_cb);
#ifdef REQUIRE_SECURE_BUFFERS
    mStripADTS = true;
#else
    if (cryptoPluginMode) {
        mStripADTS = true;
    }
#endif
}

// Since the WVMExtractor lifetime is short, we delegate ownership of some resources
// to the media source, which cleans them up after when the media source is destroyed

void WVMMediaSource::delegateFileSource(sp<WVMFileSource> fileSource)
{
    mFileSource = fileSource;
}

void WVMMediaSource::delegateDataSource(sp<DataSource> dataSource)
{
    mDataSource = dataSource;
}

void WVMMediaSource::delegateClientContext(sp<ClientContext> context)
{
    mClientContext = context;
}

void WVMMediaSource::allocBufferGroup()
{
    if (mGroup)
        delete mGroup;

    mGroup = new MediaBufferGroup;

    size_t size;
    if (mESSelector == WV_EsSelector_Video)
        size = 256 * 1024;
    else
        size = 64 * 1024;

    mGroup->add_buffer(new MediaBuffer(size));
}


status_t WVMMediaSource::setBuffers(const Vector<MediaBuffer *> &buffers) {
#ifdef REQUIRE_SECURE_BUFFERS
  if (!mIsLiveStream) {
      ALOGI("Using codec-supplied buffers");

      delete mGroup;
      mGroup = new MediaBufferGroup;
      for (size_t i = 0; i < buffers.size(); ++i) {
        mGroup->add_buffer(buffers.itemAt(i));
      }
      return OK;
  } else {
      return ERROR_UNSUPPORTED;
  }
#else
  return ERROR_UNSUPPORTED;
#endif
}


status_t WVMMediaSource::start(MetaData *)
{
    //ALOGD("WVMMediaSource::start()");
    Mutex::Autolock autoLock(mLock);

    CHECK(!mStarted);


    mNewSegment = true;
    mStarted = true;
    mLogOnce = true;

    // Let video stream control play/pause
    if (mESSelector == WV_EsSelector_Video) {
        float speed;
        WVStatus result = WV_Play(mSession, 1.0, &speed, "00:00:00-");
        if (result != WV_Status_OK) {
            ALOGE("WV_Play returned status %d in WVMMediaSource::start\n", result);
            return ERROR_IO;
        }
    }

    if (!mGroup)
        allocBufferGroup();

    return OK;
}


status_t WVMMediaSource::stop()
{
    ALOGD("WVMMediaSource::stop E");
    Mutex::Autolock autoLock(mLock);

    CHECK(mStarted);

    status_t status = OK;

    // Let video stream control play/pause
    if (mESSelector == WV_EsSelector_Video) {
        WVStatus result = WV_Pause(mSession, "now");
        if (result != WV_Status_OK) {
            ALOGE("WV_Pause returned status %d in WVMMediaSource::stop\n", result);
            status = ERROR_IO;
        }
    }

    delete mGroup;
    mGroup = NULL;

    mStarted = false;

    ALOGD("WVMMediaSource::stop X");
    return status;
}

sp<MetaData> WVMMediaSource::getFormat()
{
    Mutex::Autolock autoLock(mLock);

    if (!mIsLiveStream) {
#ifdef REQUIRE_SECURE_BUFFERS
        if (mESSelector == WV_EsSelector_Video) {
            mTrackMetaData->setInt32(kKeyRequiresSecureBuffers, true);
        }
#endif

        if (mStripADTS) {
            // Only support AAC on android for now, so assume the audio
            // track is AAC and notify the audio codec it has ADTS framing
            if (mESSelector == WV_EsSelector_Audio) {
                mTrackMetaData->setInt32(kKeyIsADTS, 1);
            }
        }
    }

    return mTrackMetaData;
}

std::string usecToNPT(int64_t time)
{
    unsigned hours = (unsigned)(time / (60LL * 60 * 1000000));
    time -= (int64_t)hours * 60 * 60 * 1000000;
    unsigned mins = (unsigned)(time / (60 * 1000000));
    time -= (int64_t)mins * 60 * 1000000;
    float secs = (float)time / 1000000;
    char buf[32];
    sprintf(buf, "%d:%d:%f", hours, mins, secs);
    return std::string(buf);
}

status_t WVMMediaSource::read(MediaBuffer **buffer, const ReadOptions *options)
{
    Mutex::Autolock autoLock(mLock);

    CHECK(mStarted);

    *buffer = NULL;
    bool seekNextSync = false;

#if 0
    // The sync bits aren't working right yet on live streams, so need to disable this
    // for now.
    if (mIsLiveStream && mNewSegment && (mESSelector == WV_EsSelector_Video)) {
        seekNextSync = true;
        mNewSegment = false;
    }
#endif

    int64_t seekTimeUs;

    int retryLimit = 500;  // Limit on number of retries before timeout, 10ms per retry

    ReadOptions::SeekMode mode;
    if (options && options->getSeekTo(&seekTimeUs, &mode)) {

        // When doing a seek, use a longer timeout since we need to set up a new connection
        retryLimit = 1500;

        //ALOGD("%s seek mode=%d, seek time=%lld lateby=%lld",
        //    (mESSelector == WV_EsSelector_Video) ? "video" : "audio",
        //     mode, seekTimeUs, options->getLateBy());
        if (mode == ReadOptions::SEEK_NEXT_SYNC) {
            // Handle seek next sync by dropping frames on this track that are
            // prior to the specified time.
            seekNextSync = true;
        } else {
            // If we are not in Crypto Plugin Mode, let the video stream
            // control the seek.
            // If we are in Crypto Plugin Mode, obey the first seek we get to a
            // given point, then ignore the subsequent one.
            if ((!mCryptoPluginMode && mESSelector == WV_EsSelector_Video) ||
                (mCryptoPluginMode && seekTimeUs != sLastSeekTimeUs)) {
                float scaleUsed;
                std::string when = usecToNPT(seekTimeUs) + std::string("-");

                WVStatus result = WV_Play(mSession, 1.0, &scaleUsed, when );

                if (result != WV_Status_OK) {
                    ALOGE("WV_Play returned status %d in WVMMediaSource::read\n", result);
                    return ERROR_IO;
                }

                sLastSeekTimeUs = seekTimeUs;
            } else if (mCryptoPluginMode) {
                sLastSeekTimeUs = -1;
            }
        }
    }

    MediaBuffer *mediaBuf;

    status_t err = mGroup->acquire_buffer(&mediaBuf);

    if (err != OK) {
        CHECK(mediaBuf == NULL);
        return err;
    }

    mDecryptContext.Initialize(mediaBuf);
    mEncryptedSizes.clear();
    mClearSizes.clear();

    size_t bytesRead;
    bool auStart;
    size_t offset = 0;

    bool syncFrame;
    int retryCount = 0;

    // Pull full access units. Since we aren't sure how big they might be,
    // start with initial buffer size, then allocate a larger buffer if we
    // get a number of bytes equal to the full buffer size and go back
    // for the rest.  Only loop in this case, usually it's one pass through.

    while (true) {
        size_t size = mediaBuf->size() - offset;

        WVStatus result = WV_GetEsData(mSession, mESSelector, (uint8_t *)mediaBuf->data() + offset,
                                       size, bytesRead, auStart, mDts, mPts, syncFrame);

        if (result != WV_Status_OK &&
            result != WV_Status_Warning_Need_Key &&
            result != WV_Status_Warning_Download_Stalled) {

            status_t status;

            if (result >= WV_Status_Min_TP_Error && result <= WV_Status_Max_TP_Error) {
                // handle the third party error code range by mapping to a reserved
                // vendor defined range of media player error codes
                status = ERROR_DRM_VENDOR_MIN + result - WV_Status_Min_TP_Error;
            } else {
                switch(result) {
                case WV_Status_End_Of_Media:
                    status = ERROR_END_OF_STREAM;
                    break;
                case WV_Status_Terminate_Requested:
                    status = ERROR_HEARTBEAT_TERMINATE_REQUESTED;
                    break;
                default:
                    if (mLogOnce) {
                        ALOGE("WV_GetEsData returned ERROR %d in WVMMediaSource::read\n", result);
                        mLogOnce = false;
                    }
                    status = ERROR_IO;
                    break;
                }
            }

            mediaBuf->release();
            return status;
        }

        if (sLastError != NO_ERROR) {
            mediaBuf->release();
            status_t status = sLastError;
            sLastError = NO_ERROR;
            return status;
        }

#ifdef REQUIRE_SECURE_BUFFERS
        if (mESSelector == WV_EsSelector_Video && !mIsLiveStream) {
            bytesRead = mDecryptContext.mOffset;
        }
#endif

        if (bytesRead == 0) {
            if (retryCount++ >= retryLimit) {
                // If no data received within the retry limit, return ERROR_IO
                // This prevents the player from becoming unresponsive
                mediaBuf->release();
                return ERROR_IO;
            } else {
                // Didn't get anything, sleep a bit so we don't hog the CPU then try again
                usleep(10000);
                continue;
            }
        }


#define PCR_HZ 90000
        mKeyTime = (int64_t)mPts * 1000000 / PCR_HZ;

        if (seekNextSync && ((mKeyTime < seekTimeUs) || !syncFrame)) {
            // drop frames up to next sync if requested
            usleep(10000);
            mDecryptContext.Initialize(mediaBuf);
            mEncryptedSizes.clear();
            mClearSizes.clear();
            continue;
        }

        if (offset + bytesRead < mediaBuf->size())
            break;

#ifdef REQUIRE_SECURE_BUFFERS
        if (!mIsLiveStream) {
            ALOGD("buffer overflow");
            mediaBuf->release();
            return ERROR_IO;
        }
#endif

        //ALOGD("Resizing...");

        // This buffer is too small, allocate a larger buffer twice the size
        // and copy the data from the current buffer into the first part of
        // the new buffer, then set offset to where the next read should go.

        MediaBuffer *newBuffer = new MediaBuffer(mediaBuf->size() * 2);
        newBuffer->add_ref();

        memcpy(newBuffer->data(), mediaBuf->data(), mediaBuf->size());
        offset = mediaBuf->size();

        mGroup->add_buffer(newBuffer);

        mediaBuf->release();
        mediaBuf = newBuffer;
    }

    mediaBuf->meta_data()->clear();
    mediaBuf->meta_data()->setInt64(kKeyTime, mKeyTime);

    mediaBuf->set_range(0, bytesRead + offset);

    if (!mIsLiveStream) {
        if (mEncryptedSizes.size()) {
            mediaBuf->meta_data()->setData(kKeyEncryptedSizes, 0,
                                           &mEncryptedSizes[0],
                                           mEncryptedSizes.size() * sizeof(size_t));
            mediaBuf->meta_data()->setInt32(kKeyCryptoMode,
                                            CryptoPlugin::kMode_AES_WV);

#ifndef REQUIRE_SECURE_BUFFERS
            mediaBuf->meta_data()->setData(kKeyCryptoKey, 0,
                                           mCryptoPluginKey,
                                           sizeof(mCryptoPluginKey));
#endif
        } else {
            // Fixes b/9261447: GTS crashed on Nexus 10
            Vector<size_t> zeroEncryptedSizes;
            size_t zeroValue = 0;
            zeroEncryptedSizes.insertAt(zeroValue, 0,
                                        mClearSizes.size());
            mediaBuf->meta_data()->setData(kKeyEncryptedSizes, 0,
                                           &zeroEncryptedSizes[0],
                                           zeroEncryptedSizes.size() * sizeof(size_t));

            mediaBuf->meta_data()->setData(kKeyPlainSizes, 0,
                                           &mClearSizes[0],
                                           mClearSizes.size() * sizeof(size_t));
            mediaBuf->meta_data()->setInt32(kKeyCryptoMode,
                                            CryptoPlugin::kMode_Unencrypted);
        }
    }

#if 0
    // debug code - log packets to files
    char filename[32];
    static int acounter = 0, vcounter = 0;
    if (mESSelector == WV_EsSelector_Video)
        sprintf(filename, "/data/wvm/v%d", vcounter++);
    else
        sprintf(filename, "/data/wvm/a%d", acounter++);

    FILE *f = fopen(filename, "w");
    if (!f)
        ALOGE("WVMFileSource: can't open %s", filename);
    else {
        fwrite(mediaBuf->data(), bytesRead + offset, 1, f);
        fclose(f);
    }
    ALOGD("WVMMediaSource::read writing (%d bytes to %s)", bytesRead + offset, filename);
#endif

#if 0
    ALOGD("[%p] %s packet length=%d kKeyTime=%lld %s\n", mediaBuf,
         (mESSelector == WV_EsSelector_Video ? "video" : "audio"),
         bytesRead + offset, mKeyTime, syncFrame ? "sync" : "");
#endif

    *buffer = mediaBuf;

    return OK;
}


void WVMMediaSource::DecryptCallback(WVEsSelector esType, void* input, void* output,
                                     size_t length, int key, void *obj)
{
    //ALOGD("DecryptCallback(type=%d, in=%p, out=%p, len=%d, key=%d\n",
    //     (int)esType, input, output, length, key);

    ClientContext *clientContext = (ClientContext *)obj;
    if (!clientContext) {
        ALOGE("WVMMediaSource::DecryptCallback - no client context!");
        return;
    }

    sp<WVMMediaSource> source;
    if (esType == WV_EsSelector_Video)
        source = clientContext->getVideoSource();
    else
        source = clientContext->getAudioSource();

    DecryptContext &context = source->getDecryptContext();
    uint32_t copied = length;

    if (clientContext->getCryptoPluginMode()) {
        // just determine crypto unit boundaries
        if (key) {
            source->addEncryptedSize(length);
        } else {
            source->addClearSize(length);
        }
        memcpy((uint8_t *)context.mMediaBuf->data() + context.mOffset, input, length);
    } else {

#ifdef REQUIRE_SECURE_BUFFERS
        // do decrypt
        OEMCryptoResult result;
        unsigned char *iv = NULL;

        if (key)
            iv = context.mIV;

        if (esType == WV_EsSelector_Video) {
            result = OEMCrypto_DecryptVideo(iv, (OEMCrypto_UINT8 *)input, length,
                                            (OEMCrypto_UINT32)(char *)context.mMediaBuf->data(),
                                            context.mOffset, &copied);
        } else {
            result = OEMCrypto_DecryptAudio(iv, (OEMCrypto_UINT8 *)input, length,
                                            (OEMCrypto_UINT8 *)context.mMediaBuf->data() + context.mOffset,
                                            &copied);
        }

        if (result != OEMCrypto_SUCCESS) {
            ALOGD("OEMCrypto decrypt failure: %d", result);
        }
#endif
    }
    context.mOffset += copied;
}


WVMMediaSource::~WVMMediaSource()
{
    //ALOGD("WVMMediaSource::~WVMMediaSource()");

    if (mStarted) {
        stop();
    }

    if (mESSelector == WV_EsSelector_Video) {
        if (mSession != NULL) {
            WV_Teardown(mSession);
#ifdef REQUIRE_SECURE_BUFFERS
            if (mCryptoInitialized) {
                OEMCrypto_Terminate();
            }
#endif
        }
        WVMExtractorImpl::cleanup();
    }
}

} // namespace android
